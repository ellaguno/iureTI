import pytest

from iureti_discovery.classify import classify
from iureti_discovery.models import Asset, Observation, SnmpInfo
from iureti_discovery.netutil import expand_targets, is_locally_administered, normalize_mac
from iureti_discovery.oui import parse_oui_csv
from iureti_discovery.reconcile import Reconciler, normalize_serial


def test_expand_targets_cidr_range_and_single():
    assert expand_targets(["192.168.1.0/30"]) == ["192.168.1.1", "192.168.1.2"]
    assert expand_targets(["10.0.0.5-7"]) == ["10.0.0.5", "10.0.0.6", "10.0.0.7"]
    assert expand_targets(["10.0.0.1, 10.0.0.1 10.0.0.2"]) == ["10.0.0.1", "10.0.0.2"]
    assert expand_targets(["10.0.0.254-10.0.1.1"]) == ["10.0.0.254", "10.0.0.255", "10.0.1.0", "10.0.1.1"]


def test_expand_targets_limits():
    with pytest.raises(ValueError):
        expand_targets(["10.0.0.0/8"])
    with pytest.raises(ValueError):
        expand_targets(["10.0.0.9-3"])


def test_mac_helpers():
    assert normalize_mac("00-1A-2B-3C-4D-5E") == "00:1a:2b:3c:4d:5e"
    assert normalize_mac("bad") == ""
    assert is_locally_administered("da:a1:19:00:00:01")
    assert not is_locally_administered("00:1a:2b:3c:4d:5e")


def test_parse_oui_csv():
    text = 'Registry,Assignment,Organization Name,Organization Address\nMA-L,001A2B,"Ayecom Technology Co., Ltd.",TW\n'
    assert parse_oui_csv(text) == {"001A2B": "Ayecom Technology Co., Ltd."}


def test_normalize_serial_discards_junk():
    assert normalize_serial("To be filled by O.E.M.") == ""
    assert normalize_serial("000000") == ""
    assert normalize_serial(" fcw2233l0ab ") == "FCW2233L0AB"


def _snmp_asset(descr, oid="", model=""):
    return Asset(attributes={"snmp": {"sys_descr": descr, "sys_object_id": oid}}, model=model)


@pytest.mark.parametrize(
    "asset,expected",
    [
        (_snmp_asset("FortiGate-60F v7.2.5", "1.3.6.1.4.1.12356.101.1.1"), "firewall"),
        (_snmp_asset("Cisco IOS Software, Catalyst L3 Switch Software (CAT9K)", "1.3.6.1.4.1.9.1.2494"), "switch"),
        (_snmp_asset("HP ETHERNET MULTI-ENVIRONMENT", "1.3.6.1.4.1.11.2.3.9.1", "HP LaserJet Pro M404dn"), "printer"),
        (_snmp_asset("APC Web/SNMP Management Card", "1.3.6.1.4.1.318.1.3.27"), "ups"),
        (_snmp_asset("Linux DiskStation 4.4.180+", "1.3.6.1.4.1.6574.1"), "nas"),
        (Asset(open_ports=[135, 139, 445, 3389]), "workstation"),
        (Asset(open_ports=[53, 88, 135, 389, 445, 3268]), "server"),
        (Asset(open_ports=[22, 5432]), "server"),
        (Asset(open_ports=[80, 443, 9100]), "printer"),
        (Asset(open_ports=[22, 8006]), "hypervisor"),
        (Asset(hostname="lap-jperez.corp.local", open_ports=[135, 445]), "laptop"),
        (Asset(), "unknown"),
    ],
)
def test_classify(asset, expected):
    kind, confidence, _ = classify(asset)
    assert kind == expected
    assert 0 <= confidence <= 1


WIN = {"os_family": "windows"}


@pytest.mark.parametrize(
    "asset,expected",
    [
        # Portátil Windows por el nombre (NetBIOS/DNS): pesa más que los puertos y el TTL de Windows
        (Asset(hostname="LAPTOP-8H2KQ1", open_ports=[135, 139, 445, 3389], os="Microsoft Windows 11", attributes=WIN),
         "laptop"),
        (Asset(hostname="ventas-nb03", open_ports=[135, 445], attributes=WIN), "laptop"),
        # …o por el modelo (SNMP, UPnP, mDNS)
        (Asset(model="Latitude 7440", open_ports=[135, 445, 3389], attributes=WIN), "laptop"),
        (Asset(open_ports=[135, 445], attributes={**WIN, "snmp": {"sys_descr": "HP EliteBook 840 G9 Notebook PC"}}),
         "laptop"),
        (Asset(open_ports=[135, 445], attributes={**WIN, "upnp": {"modelName": "Surface Laptop 5"}}), "laptop"),
        # Escritorios siguen siendo escritorio; «lap» dentro de otra palabra no cuenta
        (Asset(hostname="DESKTOP-7F3K2Q", open_ports=[135, 139, 445, 3389], os="Microsoft Windows 10", attributes=WIN),
         "workstation"),
        (Asset(hostname="overlap-pc", open_ports=[135, 445], attributes=WIN), "workstation"),
        (Asset(model="Yoga AIO 7", open_ports=[135, 445], attributes=WIN), "workstation"),
        # «Latitude» o «Notebook» en un título web no es un modelo
        (Asset(open_ports=[135, 445], attributes={**WIN, "http": {"title": "Jupyter Notebook"}}), "workstation"),
        # Servidores con señales fuertes no se vuelven portátiles por un nombre o modelo parecido
        (Asset(hostname="nb-legacy-dc", open_ports=[53, 88, 135, 389, 445, 3268], os="Microsoft Windows Server 2019"),
         "server"),
        (Asset(model="ThinkPad P1", open_ports=[22, 5432, 3306]), "server"),
    ],
)
def test_classify_laptop_vs_desktop(asset, expected):
    kind, _, reasons = classify(asset)
    assert kind == expected
    if expected == "laptop":
        assert any("portátil" in r for r in reasons)


def test_reconcile_merges_by_mac_across_ip_change():
    rec = Reconciler([])
    a1, new1 = rec.merge(Observation(ip="10.0.0.5", mac="00:1a:2b:3c:4d:5e", open_ports=[445]))
    a2, new2 = rec.merge(Observation(ip="10.0.0.9", mac="00:1A:2B:3C:4D:5E", open_ports=[445]))
    assert new1 and not new2
    assert a1.id == a2.id
    assert a2.ips == ["10.0.0.9", "10.0.0.5"]
    assert a2.fingerprint == "mac:00:1a:2b:3c:4d:5e"


def test_reconcile_serial_beats_mac():
    rec = Reconciler([])
    snmp = SnmpInfo(sys_descr="Cisco IOS", sys_name="sw-core", serial="FCW1")
    a1, _ = rec.merge(Observation(ip="10.0.0.2", mac="00:1a:2b:00:00:01", snmp=snmp))
    # Misma serie, otra interfaz/MAC → mismo activo
    a2, new = rec.merge(Observation(ip="10.0.1.2", mac="00:1a:2b:00:00:02", snmp=snmp))
    assert not new and a1.id == a2.id
    assert a2.fingerprint == "serial:FCW1"
    assert set(a2.macs) == {"00:1a:2b:00:00:01", "00:1a:2b:00:00:02"}


def test_reconcile_random_mac_is_weak_identity():
    """Contrato cambiado (0.4.2): la misma MAC privada vista en otra IP ES el mismo equipo
    (46 bits aleatorios iguales no son dos aparatos). Lo que sigue sin garantizarse es lo
    contrario: el equipo puede cambiar de MAC privada y entonces lo salva el hostname."""
    rec = Reconciler([])
    a, _ = rec.merge(Observation(ip="10.0.0.20", mac="da:a1:19:00:00:01"))
    b, new = rec.merge(Observation(ip="10.0.0.21", mac="da:a1:19:00:00:01"))
    assert not new and b.id == a.id
    assert a.fingerprint == "localmac:da:a1:19:00:00:01"  # mejor huella que la IP (DHCP)
    # Docker: 02:42:<ip> se repite entre hosts → sigue sin fusionar
    rec.merge(Observation(ip="172.17.0.2", mac="02:42:ac:11:00:02"))
    _, new = rec.merge(Observation(ip="172.17.0.3", mac="02:42:ac:11:00:02"))
    assert new


def test_reconcile_respects_locked_type():
    locked = Asset(macs=["00:1a:2b:3c:4d:5e"], device_type="laptop", type_locked=True)
    rec = Reconciler([locked])
    asset, new = rec.merge(Observation(ip="10.0.0.5", mac="00:1a:2b:3c:4d:5e", open_ports=[22, 5432]))
    assert not new and asset.device_type == "laptop"


def test_reconcile_ip_only_moves_to_strong_identity():
    rec = Reconciler([])
    weak, _ = rec.merge(Observation(ip="10.0.0.7", open_ports=[80]))
    strong, new = rec.merge(Observation(ip="10.0.0.7", hostname="printer-2", open_ports=[9100]))
    # la IP-only se reutiliza porque no tenía identidad fuerte
    assert not new and weak.id == strong.id and strong.fingerprint == "host:printer-2"


def test_gateway_is_router():
    kind, _, reasons = classify(Asset(open_ports=[23, 53, 80], attributes={"is_gateway": True}))
    assert kind == "router" and "puerta de enlace de la red" in reasons


def test_gateway_firewall_evidence_wins():
    snmp = {"sys_descr": "FortiGate-60F v7.2.5", "sys_object_id": "1.3.6.1.4.1.12356.101.1.1"}
    kind, _, _ = classify(Asset(attributes={"is_gateway": True, "snmp": snmp}))
    assert kind == "firewall"


def test_synthetic_hostname_is_not_identity():
    rec = Reconciler([])
    a, _ = rec.merge(Observation(ip="10.0.0.1", hostname="_gateway"))
    assert a.fingerprint == "ip:10.0.0.1"


def test_junk_macs_never_identify():
    from iureti_discovery.reconcile import identity_keys
    assert identity_keys("", ["00:00:00:00:00:00", "FF-FF-FF-FF-FF-FF", "00:1a:2b:3c:4d:5e"], "") == ["mac:00:1a:2b:3c:4d:5e"]


def test_local_mac_is_a_weak_key_after_the_strong_ones():
    """Caso real (INST-002, oct-2026): una MacBook con dirección privada 7a:7a:… se vio como
    «MAC-4C0ED6» (NetBIOS) un día y «MacBook-Air-de-Sofia» (mDNS) al siguiente y salió dos veces."""
    from iureti_discovery.reconcile import identity_keys, normalize_hostname
    assert identity_keys("", ["7a:7a:6b:63:3a:c4"], "MacBook-Air-de-Sofia") == [
        "host:macbook-air-de-sofia", "localmac:7a:7a:6b:63:3a:c4"]
    # la serie y la MAC universal siguen primero; la local va al final
    assert identity_keys("SN1", ["7a:7a:6b:63:3a:c4", "00:1a:2b:3c:4d:5e"], "pc")[:3] == [
        "serial:SN1", "mac:00:1a:2b:3c:4d:5e", "host:pc"]
    # Docker deriva la MAC de la IP: se repite entre hosts, no es clave ni débil
    assert identity_keys("", ["02:42:ac:11:00:02"], "") == []
    # el nombre NetBIOS sintético de macOS no identifica (el mDNS sí)
    assert normalize_hostname("MAC-4C0ED6") == ""
    assert normalize_hostname("MAC-4C0ED6.local") == ""
    assert normalize_hostname("macbook-pro") == "macbook-pro"


def test_same_private_mac_with_new_hostname_is_the_same_asset():
    from iureti_discovery.models import Observation
    from iureti_discovery.reconcile import Reconciler
    rec = Reconciler([])
    a, nuevo = rec.merge(Observation(ip="192.168.1.75", mac="7a:7a:6b:63:3a:c4",
                                     netbios={"name": "MAC-4C0ED6"}, mdns={"host": "MacBook-Air-de-Sofia"}))
    assert nuevo and a.hostname == "MacBook-Air-de-Sofia", "el nombre mDNS gana al NetBIOS sintético"
    b, nuevo = rec.merge(Observation(ip="192.168.1.90", mac="7a:7a:6b:63:3a:c4", mdns={"host": "MacBook-Air-de-Sofia-2"}))
    assert not nuevo and b.id == a.id, "misma MAC privada con otro nombre y otra IP: el mismo equipo"
    assert b.fingerprint == "host:macbook-air-de-sofia-2"
    c, nuevo = rec.merge(Observation(ip="192.168.1.91", mac="7a:7a:6b:63:3a:c4"))
    assert not nuevo and c.id == a.id
    # solo MAC privada y sin nombre: la huella es la MAC local, no la IP (que es DHCP)
    d, _ = rec.merge(Observation(ip="10.0.0.5", mac="96:9e:f1:11:4d:33"))
    assert d.fingerprint == "localmac:96:9e:f1:11:4d:33"
