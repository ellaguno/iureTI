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
        (Asset(hostname="lap-jperez.corp.local", open_ports=[135, 445]), "workstation"),
        (Asset(), "unknown"),
    ],
)
def test_classify(asset, expected):
    kind, confidence, _ = classify(asset)
    assert kind == expected
    assert 0 <= confidence <= 1


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


def test_reconcile_random_mac_not_identity():
    rec = Reconciler([])
    rec.merge(Observation(ip="10.0.0.20", mac="da:a1:19:00:00:01"))
    _, new = rec.merge(Observation(ip="10.0.0.21", mac="da:a1:19:00:00:01"))
    assert new  # MAC aleatoria no fusiona


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
