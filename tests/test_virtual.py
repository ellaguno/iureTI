"""Duplicados entre escaneos y equipos virtuales con su anfitrión (v0.5)."""

from types import SimpleNamespace

from iureti_discovery import snmp, sync, virtual
from iureti_discovery.classify import classify
from iureti_discovery.models import Asset, Observation, SnmpInfo
from iureti_discovery.reconcile import Reconciler, asset_keys
from iureti_discovery.scanner import Scanner, ScanOptions

MAC_A, MAC_B = "00:1a:2b:00:00:01", "00:1a:2b:00:00:02"


class NoOui:
    available = False

    def lookup(self, mac):
        return ""


# --- 1. el mismo equipo visto en otro escaneo -----------------------------------------------

def test_observation_that_matches_two_assets_merges_them():
    """Escaneo 1 lo vio por MAC (sin nombre); escaneo 2 por nombre (otra subred, sin MAC): dos activos.
    La observación que trae MAC y nombre demuestra que eran uno."""
    rec = Reconciler([])
    by_mac, _ = rec.merge(Observation(ip="10.0.0.5", mac=MAC_A, open_ports=[445]))
    by_name, _ = rec.merge(Observation(ip="10.0.1.9", hostname="pc-juan.corp.local", open_ports=[445]))
    assert by_mac.id != by_name.id
    both, new = rec.merge(Observation(ip="10.0.1.9", mac=MAC_A, hostname="pc-juan.corp.local", open_ports=[445]))
    assert not new and both.id == by_mac.id, "gana el activo de la clave más fuerte (MAC universal)"
    assert by_name.id not in rec.assets and rec.removed == {by_name.id: by_mac.id}
    assert set(both.ips) == {"10.0.0.5", "10.0.1.9"} and both.hostname == "pc-juan.corp.local"
    assert both.attributes["merged_from"][0]["fingerprint"] == "host:pc-juan"
    assert both.synced_at == "", "se vuelve a enviar para que iurefficient sepa de la fusión"


def test_existing_duplicates_are_consolidated_on_load():
    """Duplicados que ya estaban en la base (reglas anteriores) se fusionan al cargar; el más antiguo manda."""
    old = Asset(macs=[MAC_A], ips=["10.0.0.5"], first_seen="2026-09-01T00:00:00Z", inventory_id="uuid-1",
                device_type="laptop", type_locked=True)
    dup = Asset(macs=[MAC_A], ips=["10.0.0.7"], hostname="lap-ana", first_seen="2026-09-20T00:00:00Z",
                last_seen="2026-10-01T00:00:00Z", notes="revisar")
    rec = Reconciler([dup, old])
    assert list(rec.assets) == [old.id] and rec.removed == {dup.id: old.id}
    assert old.hostname == "lap-ana" and set(old.ips) == {"10.0.0.5", "10.0.0.7"}
    assert old.inventory_id == "uuid-1" and old.type_locked and old.device_type == "laptop" and old.notes == "revisar"


def test_consolidate_service(tmp_path):
    from iureti_discovery.service import consolidate
    from iureti_discovery.store import Store
    store = Store(tmp_path / "t.db")
    store.save_assets([Asset(macs=[MAC_A], ips=["10.0.0.5"], fingerprint=f"mac:{MAC_A}"),
                       Asset(macs=[MAC_A], ips=["10.0.0.9"], fingerprint=f"mac:{MAC_A}"),
                       Asset(macs=[MAC_B], ips=["10.0.0.6"], fingerprint=f"mac:{MAC_B}")])
    assert consolidate(store) == 1 and len(store.list_assets()) == 2


def test_every_observed_name_identifies_the_asset():
    """Sin MAC (otra subred): un escaneo trae el nombre DNS y NetBIOS, el siguiente solo NetBIOS."""
    rec = Reconciler([])
    a, _ = rec.merge(Observation(ip="10.0.1.9", hostname="ws042.corp.local", netbios={"name": "PC-JUAN", "group": "CORP"}))
    assert a.fingerprint == "host:ws042" and "host:pc-juan" in asset_keys(a)
    b, new = rec.merge(Observation(ip="10.0.1.30", netbios={"name": "PC-JUAN", "group": "CORP"}))
    assert not new and b.id == a.id and b.hostname == "PC-JUAN"
    assert set(b.attributes["names"]) == {"ws042.corp.local", "PC-JUAN"}


def test_mac_from_router_arp_table_identifies_remote_hosts():
    """Hosts de otra subred no tienen MAC por ARP; la tabla ARP SNMP del router se la da."""
    sc = Scanner(ScanOptions(targets=["10.0.1.0/24"]), oui=NoOui())
    router = Observation(ip="10.0.1.1", mac="00:aa:00:00:00:01", snmp=SnmpInfo(sys_name="rtr-01"),
                         hosting={"container_interfaces": [], "vm_interfaces": [], "vm_platforms": [], "vms": [],
                                  "arp": [{"ip": "10.0.1.7", "mac": MAC_A, "iface": "Gi0/1", "kind": "", "platform": ""}]})
    remote = Observation(ip="10.0.1.7", open_ports=[445])
    obs = {o.ip: o for o in (router, remote)}
    sc._apply_hosting(obs, set(obs))
    assert remote.mac == MAC_A and remote.mac_from == "snmp-arp:10.0.1.1" and "snmp-arp" in remote.sources
    rec = Reconciler([])
    a, _ = rec.merge(remote)
    assert a.fingerprint == f"mac:{MAC_A}" and a.attributes["mac_from"] == "snmp-arp:10.0.1.1"


# --- 2. contenedores y VMs con su anfitrión --------------------------------------------------

def _host_obs():
    return Observation(ip="10.0.0.20", mac="00:aa:00:00:00:20", snmp=SnmpInfo(sys_name="srv-docker-01", sys_descr="Linux"),
                       hosting={"container_interfaces": ["docker0", "veth1a2b3c"], "vm_interfaces": ["virbr0"],
                                "vm_platforms": ["kvm"], "vms": [],
                                "arp": [{"ip": "172.17.0.2", "mac": "02:42:ac:11:00:02", "iface": "docker0", "kind": "container", "platform": "docker"},
                                        {"ip": "192.168.122.10", "mac": "52:54:00:aa:bb:cc", "iface": "virbr0", "kind": "vm", "platform": "kvm"},
                                        {"ip": "10.0.0.30", "mac": "00:aa:00:00:00:30", "iface": "eth0", "kind": "", "platform": ""}]})


def test_host_arp_table_yields_guests_with_their_host():
    sc = Scanner(ScanOptions(targets=["10.0.0.0/24"]), oui=NoOui())
    host = _host_obs()
    vm_on_lan = Observation(ip="10.0.0.31", mac="00:50:56:00:00:31", open_ports=[22])
    esx = Observation(ip="10.0.0.40", mac="00:aa:00:00:00:40", open_ports=[902], snmp=SnmpInfo(sys_name="esx-01", sys_object_id="1.3.6.1.4.1.6876.4.1"),
                      hosting={"container_interfaces": [], "vm_interfaces": [], "vm_platforms": [], "arp": [],
                               "vms": [{"name": "srv-contabilidad", "macs": ["00:50:56:00:00:31"]}]})
    obs = {o.ip: o for o in (host, vm_on_lan, esx)}
    sc._apply_hosting(obs, set(o for o in obs))
    # Contenedor NAT y VM en red NAT del anfitrión: no se alcanzan desde la red, se dan de alta vía anfitrión
    assert obs["172.17.0.2"].virtual == {"kind": "container", "platform": "docker", "host_ip": "10.0.0.20", "host_name": "srv-docker-01",
                                         "confidence": "alta", "evidence": "tabla ARP de srv-docker-01 en docker0", "reach": "host"}
    assert obs["192.168.122.10"].virtual["kind"] == "vm" and obs["192.168.122.10"].alive_by == ["snmp-arp"]
    assert "10.0.0.30" not in obs, "una entrada ARP en interfaz física no es un invitado"
    # VM de ESXi vista en la red: nombre y anfitrión por la tabla de VMs
    assert vm_on_lan.virtual["name"] == "srv-contabilidad" and vm_on_lan.virtual["host_ip"] == "10.0.0.40"

    rec = Reconciler([])
    assets = [rec.merge(o)[0] for o in obs.values()]
    virtual.annotate(assets, virtual.LocalHosting({}, {}), "sonda")
    by_ip = {a.ips[0]: a for a in assets}
    container, vm, docker_host, esx_a = by_ip["172.17.0.2"], by_ip["10.0.0.31"], by_ip["10.0.0.20"], by_ip["10.0.0.40"]
    assert container.fingerprint == "guest:srv-docker-01/02:42:ac:11:00:02"
    assert container.attributes["virtual"]["host_id"] == docker_host.id
    assert vm.attributes["virtual"]["host_id"] == esx_a.id and vm.hostname == "srv-contabilidad"
    assert {g["ip"] for g in docker_host.attributes["guests"]} == {"172.17.0.2", "192.168.122.10"}
    assert esx_a.attributes["guests"][0]["id"] == vm.id
    kind, _, reasons = classify(docker_host)  # servidor Linux con Docker y una VM de libvirt: servidor que aloja
    assert kind in ("server", "hypervisor") and any("aloja máquinas virtuales" in r for r in reasons) \
        and any("aloja contenedores" in r for r in reasons)
    assert any("alojado en srv-docker-01" in r for r in classify(container)[2])


def test_same_container_ip_on_two_hosts_are_two_assets():
    """172.17.0.2 existe en cada servidor con Docker: la IP solo vale junto con el anfitrión."""
    def guest(host):
        return Observation(ip="172.17.0.2", mac="02:42:ac:11:00:02", alive_by=["snmp-arp"],
                           virtual={"kind": "container", "platform": "docker", "host_ip": host, "host_name": "srv-" + host[-1],
                                    "reach": "host", "confidence": "alta", "evidence": ""})
    rec = Reconciler([])
    a, _ = rec.merge(guest("10.0.0.1"))
    b, new_b = rec.merge(guest("10.0.0.2"))
    assert new_b and a.id != b.id and a.ips == ["172.17.0.2"] == b.ips, "no se roban la IP"
    c, new_c = rec.merge(guest("10.0.0.1"))
    assert not new_c and c.id == a.id


def test_probe_bridges_and_virtual_networks_make_the_probe_the_host():
    rec = Reconciler([])
    probe, _ = rec.merge(Observation(ip="192.168.1.10", mac="00:aa:00:00:00:10", hostname="sonda-01", is_probe=True))
    docker_guest, _ = rec.merge(Observation(ip="172.19.0.4", mac="62:0d:b7:1c:3e:41", virtual_net="br-8bc5cbaf949f"))
    bridged_vm, _ = rec.merge(Observation(ip="192.168.1.50", mac="52:54:00:12:34:56", open_ports=[22]))
    other_vm, _ = rec.merge(Observation(ip="192.168.1.60", mac="52:54:00:65:43:21", open_ports=[22]))
    local = virtual.LocalHosting({"virbr0": ("vm", "kvm"), "vnet3": ("vm", "kvm"), "docker0": ("container", "docker")},
                                 {"52:54:00:12:34:56": "vnet3"})
    assets = list(rec.assets.values())
    virtual.annotate(assets, local, "sonda-01")
    v = docker_guest.attributes["virtual"]
    assert v["kind"] == "container" and v["platform"] == "docker" and v["host_id"] == probe.id and v["confidence"] == "alta"
    # la MAC privada aleatoria del contenedor ya es clave (débil) única; la clave guest: va detrás
    assert docker_guest.fingerprint == "localmac:62:0d:b7:1c:3e:41" and "guest:sonda-01/62:0d:b7:1c:3e:41" in asset_keys(docker_guest)
    v = bridged_vm.attributes["virtual"]
    assert v["host_id"] == probe.id and v["confidence"] == "alta" and "vnet3" in v["evidence"]
    v = other_vm.attributes["virtual"]  # solo prefijo de MAC: la sonda es anfitrión KVM → probable
    assert v["host_id"] == probe.id and v["confidence"] == "media"
    assert len(probe.attributes["guests"]) == 3


def test_without_virtualization_on_the_probe_nothing_is_guessed():
    rec = Reconciler([])
    vm, _ = rec.merge(Observation(ip="192.168.1.60", mac="00:50:56:65:43:21", open_ports=[22]))
    esx, _ = rec.merge(Observation(ip="192.168.1.5", mac="00:aa:00:00:00:05", hostname="esx-01", open_ports=[902, 443]))
    assets = list(rec.assets.values())
    virtual.annotate(assets, virtual.LocalHosting({}, {}), "pi-sonda")
    v = vm.attributes["virtual"]
    assert v["kind"] == "vm" and v["platform"] == "vmware" and not v.get("host_id") and not v.get("host_name")
    assert v["host_candidates"] == [{"id": esx.id, "name": "esx-01"}]
    assert "guests" not in esx.attributes


def test_hyperv_mac_points_to_the_host_ip():
    rec = Reconciler([])
    vm, _ = rec.merge(Observation(ip="10.0.10.77", mac="00:15:5d:0a:05:07", open_ports=[135, 445]))
    hv, _ = rec.merge(Observation(ip="10.0.10.5", mac="00:aa:00:00:00:05", hostname="hv-01", open_ports=[135, 445, 2179]))
    rec.merge(Observation(ip="10.0.20.5", mac="00:aa:00:00:00:06", hostname="otro", open_ports=[135, 445, 2179]))
    assets = list(rec.assets.values())
    virtual.annotate(assets, virtual.LocalHosting({}, {}), "sonda")
    v = vm.attributes["virtual"]
    assert v["platform"] == "hyperv" and v["host_id"] == hv.id and v["confidence"] == "media"
    assert classify(hv)[0] == "hypervisor"


def test_virtual_survives_a_scan_without_evidence():
    rec = Reconciler([])
    a, _ = rec.merge(Observation(ip="10.0.0.31", mac="00:50:56:00:00:31",
                                 virtual={"kind": "vm", "platform": "vmware", "host_ip": "10.0.0.40", "host_name": "esx-01",
                                          "reach": "network", "confidence": "alta", "evidence": "tabla de VMs"}))
    b, _ = rec.merge(Observation(ip="10.0.0.31", mac="00:50:56:00:00:31"))  # esta vez sin SNMP
    assert b.id == a.id and b.attributes["virtual"]["host_name"] == "esx-01"


# --- SNMP y contrato --------------------------------------------------------------------------

def test_snmp_mac_decoding():
    assert snmp._mac(SimpleNamespace(asOctets=lambda: bytes.fromhex("001a2b3c4d5e"))) == "00:1a:2b:3c:4d:5e"
    assert snmp._mac(SimpleNamespace(asOctets=lambda: b"\x00")) == ""
    assert snmp._mac("0x001a2b3c4d5e") == "00:1a:2b:3c:4d:5e"


def test_payload_and_csv_carry_virtual_and_merge_info():
    host = Asset(hostname="esx-01", ips=["10.0.0.40"], macs=["00:aa:00:00:00:40"], inventory_id="uuid-esx",
                 fingerprint="mac:00:aa:00:00:00:40", attributes={"guests": [{"id": "vm1", "name": "srv-conta", "ip": "10.0.0.31", "kind": "vm", "platform": "vmware"}]})
    vm = Asset(id="vm1", hostname="srv-conta", ips=["10.0.0.31"], macs=["00:50:56:00:00:31"], fingerprint="host:srv-conta",
               device_type="server", attributes={"virtual": {"kind": "vm", "platform": "vmware", "host_id": host.id, "host_name": "esx-01",
                                                             "host_ip": "10.0.0.40", "reach": "network", "confidence": "alta", "evidence": "tabla de VMs"},
                                                 "merged_from": [{"id": "old-id", "fingerprint": "ip:10.0.0.9"}]})
    batch = sync.build_batch([vm], {"probe_id": "s"}, None, {host.id: host, vm.id: vm})
    at = batch["assets"][0]["attributes"]
    v = at["virtualization"]  # contrato de iurefficient 1.8.0, con el anfitrión identificable por serie/MAC/hostname
    assert v["kind"] == "vm" and v["runtime"] == "vmware" and v["label"] == "máquina virtual VMware"
    assert v["host"] == {"hostname": "esx-01", "macs": ["00:aa:00:00:00:40"], "probe_asset_id": host.id,
                         "inventory_id": "uuid-esx", "ip": "10.0.0.40", "confidence": "alta"}
    assert at["superseded_probe_asset_ids"] == ["old-id"]
    assert sync.asset_payload(host)["attributes"]["guests"][0]["probe_asset_id"] == "vm1"
    assert "Virtual: máquina virtual VMware alojado en esx-01 (10.0.0.40)" in sync.technical_description(vm)
    assert "Aloja: 1 máquina virtual" in sync.technical_description(host)
