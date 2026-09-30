import struct
from types import SimpleNamespace

import pytest

from iureti_discovery import enrich, httpinfo, netbios, service, upnp
from iureti_discovery.classify import classify
from iureti_discovery.models import Asset, Observation
from iureti_discovery.netutil import os_family_from_ttl
from iureti_discovery.reconcile import Reconciler
from iureti_discovery.store import Store

MODEM_XML = """<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0"><device>
<deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
<friendlyName>Huawei IGD</friendlyName><manufacturer>Huawei</manufacturer>
<modelDescription>Huawei EchoLife Series</modelDescription><modelName>Huawei EchoLife Series</modelName>
<modelNumber>Huawei Device</modelNumber><serialNumber>485754436371E3B5</serialNumber>
<iconList><icon><mimetype>image/png</mimetype><width>48</width><url>/icon.png</url></icon></iconList>
<deviceList><device><deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType></device></deviceList>
</device></root>"""

PIXEL_MDNS = {
    "host": "Android_9XP64ZT9",
    "services": ["_kdeconnect._udp", "_fc9f5ed42c8a._tcp"],
    "names": ["51fd"],
    "txt": {"_kdeconnect._udp:name": "Pixel 9 Pro", "_kdeconnect._udp:type": "phone"},
}


def test_upnp_description_and_gpon_serial():
    info = upnp.parse_description(MODEM_XML, "http://192.168.100.1:49652/desc.xml")
    assert info["manufacturer"] == "Huawei" and info["serialDecoded"] == "HWTC6371E3B5"
    assert info["icons"][0]["url"] == "http://192.168.100.1:49652/icon.png"
    assert upnp.decode_gpon_serial("0123456789ABCDEF") == ""


def test_http_parse_filters_noise():
    body = "<html><title> Router  HG8145X6 </title><style>color:#FF0033</style> UTF-8 FF0033 E60000</html>"
    info = httpinfo.parse({"server": "lighttpd", "www-authenticate": 'Basic realm="TL-WR840N"'}, body)
    assert info["title"] == "Router HG8145X6" and info["realm"] == "TL-WR840N"
    assert set(info["model_candidates"]) == {"HG8145X6", "TL-WR840N"}


def test_netbios_parse():
    names = b"".join(n.ljust(15).encode() + bytes([0]) + struct.pack(">H", f) for n, f in
                     (("CONTABILIDAD-01", 0x0400), ("OFICINA", 0x8400)))
    packet = (struct.pack(">HHHHHH", 1, 0x8400, 0, 1, 0, 0) + netbios._encode_name(b"*")
              + struct.pack(">HHIH", 0x21, 1, 0, 1 + len(names) + 6) + bytes([2]) + names + b"\x00" * 6)
    assert netbios.parse_response(packet) == {"name": "CONTABILIDAD-01", "group": "OFICINA"}


def test_ttl_family():
    assert os_family_from_ttl(64) == "unix" and os_family_from_ttl(127) == "windows"
    assert os_family_from_ttl(254) == "network" and os_family_from_ttl(None) == ""


def test_pixel_is_mobile_with_model_and_brand():
    rec = Reconciler([])
    asset, _ = rec.merge(Observation(ip="192.168.100.4", mac="96:9e:f1:11:4d:33", mdns=PIXEL_MDNS, ttl=64))
    assert asset.device_type == "mobile" and asset.confidence > 0.8
    assert asset.model == "Pixel 9 Pro" and asset.vendor == "Google"
    assert asset.hostname == "Android_9XP64ZT9"


def test_modem_via_upnp_is_router_and_serial_is_identity():
    info = upnp.parse_description(MODEM_XML, "http://192.168.100.1:49652/desc.xml")
    rec = Reconciler([])
    asset, _ = rec.merge(Observation(ip="192.168.100.1", mac="b0:a4:f0:4a:1b:ae", open_ports=[23, 53, 80],
                                     upnp=info, http={"model_candidates": ["HG8145X6"]}))
    assert asset.device_type == "router"
    assert asset.fingerprint == "serial:485754436371E3B5"
    assert asset.model == "HG8145X6"  # UPnP daba un modelo genérico; la página web el real


def test_personal_announced_names_are_not_products():
    from iureti_discovery.reconcile import product_brand
    assert product_brand("Pixel 9 Pro") == "Google"
    for personal in ("iPhone de Juan", "Juan's iPhone", "Galaxy del jefe"):
        assert product_brand(personal) == ""
    a = Asset(attributes={"announced_name": "iPhone de Juan", "mdns": {"services": ["_apple-mobdev2._tcp"]}})
    assert "Juan" not in repr(enrich.product_facts(a))


def test_iphone_port_is_mobile():
    assert classify(Asset(open_ports=[62078]))[0] == "mobile"


# --- enriquecimiento -----------------------------------------------------------
def _modem_asset():
    return Asset(ips=["192.168.100.1"], macs=["b0:a4:f0:4a:1b:ae"], hostname="modem-casa", serial="485754436371E3B5",
                 vendor="HUAWEI TECHNOLOGIES CO.,LTD", model="Huawei EchoLife Series", device_type="router",
                 location="Casa de Eduardo", attributes={"upnp": {"modelName": "Huawei EchoLife Series",
                                                                 "serialNumber": "485754436371E3B5"},
                                                        "http": {"model_candidates": ["HG8145X6"]}})


def test_product_facts_never_leak_network_or_identity():
    facts = enrich.product_facts(_modem_asset())
    text = repr(facts)
    for secret in ("192.168.100.1", "b0:a4:f0", "modem-casa", "485754436371E3B5", "Eduardo"):
        assert secret not in text
    assert enrich.has_product_clues(facts)
    assert not enrich.has_product_clues(enrich.product_facts(Asset(vendor="Intel Corporate")))


def test_hostname_inside_sysdescr_is_scrubbed():
    a = Asset(hostname="srv-contabilidad.corp.local", attributes={"snmp": {
        "sys_descr": "Linux srv-contabilidad 5.15.0-91-generic #101-Ubuntu SMP x86_64", "sys_name": "srv-contabilidad"}})
    facts = enrich.product_facts(a)
    assert "contabilidad" not in repr(facts) and "5.15.0-91-generic" in facts["snmp_sysDescr"]


def test_is_public_url_blocks_internal():
    assert not enrich.is_public_url("http://192.168.100.1/logo.png")
    assert not enrich.is_public_url("http://127.0.0.1/x.png")
    assert not enrich.is_public_url("file:///etc/passwd")


REPORT = {"identified": True, "manufacturer": "Huawei", "product_name": "Huawei EchoLife HG8145X6",
          "model": "HG8145X6", "device_type": "router", "description": "ONT GPON con Wi-Fi 6.",
          "specs": ["GPON", "Wi-Fi 6"], "release_year": "2021", "support_status": "vigente",
          "product_url": "https://e.huawei.com/x", "image_url": "", "confidence": "alta", "notes": ""}


class FakeMessages:
    def __init__(self):
        self.calls = 0

    def create(self, **kwargs):
        self.calls += 1
        assert kwargs["model"] == "claude-opus-5-5" and kwargs["fallbacks"] == "default"
        assert "192.168.100.1" not in repr(kwargs["messages"])
        if self.calls == 1:  # la búsqueda web se pausa y hay que reenviar
            return SimpleNamespace(stop_reason="pause_turn", content=[SimpleNamespace(type="text", text="...")])
        return SimpleNamespace(stop_reason="tool_use",
                               content=[SimpleNamespace(type="tool_use", name="report_device", input=REPORT)])


def fake_client():
    messages = FakeMessages()
    return SimpleNamespace(beta=SimpleNamespace(messages=messages)), messages


def test_identify_handles_pause_turn():
    client, messages = fake_client()
    assert enrich.identify({"modelo": "x"}, client)["model"] == "HG8145X6"
    assert messages.calls == 2


def test_enrich_asset_applies_and_caches(tmp_path, monkeypatch):
    monkeypatch.setattr(enrich, "resolve_image", lambda result: ("", ""))
    store = Store(tmp_path / "t.db")
    a, b = _modem_asset(), _modem_asset()
    b.ips, b.macs, b.serial = ["10.0.0.1"], ["b0:a4:f0:00:00:01"], "X2"
    store.save_assets([a, b])
    with pytest.raises(enrich.EnrichError):
        service.enrich_asset(store, a.id)  # desactivado por omisión
    store.update_settings({"enrich_enabled": True})
    client, messages = fake_client()
    r = service.enrich_asset(store, a.id, client=client)
    assert not r["cached"] and r["asset"]["model"] == "HG8145X6"
    # Mismo modelo en otro equipo: sale de la caché, sin otra consulta
    r2 = service.enrich_asset(store, b.id, client=client)
    assert r2["cached"] and messages.calls == 2
    assert store.get_asset(b.id).attributes["enrichment"]["product_name"] == "Huawei EchoLife HG8145X6"
