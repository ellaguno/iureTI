"""Contenedores y máquinas virtuales: qué equipo es virtual y qué equipo (real) lo contiene.

Evidencia, de más a menos segura:

1. **Tabla ARP del anfitrión por SNMP** en una interfaz virtual (docker0, virbr0, vmbr0, vnet…): el
   invitado cuelga de ese equipo. Si además no se alcanza desde la red (contenedor en red NAT), solo
   existe a través de su anfitrión (`reach = host`).
2. **Tabla de VMs de ESXi** (VMWARE-VMINFO-MIB): nombre y MAC de cada VM del hipervisor.
3. **El equipo de la sonda**: lo que se ve por sus interfaces virtuales o cuelga de sus puentes
   (`bridge fdb show`, sin root) lo aloja la propia sonda.
4. **MAC derivada de Hyper-V** (00:15:5d:XX:YY:ZZ, con XX:YY = últimos dos octetos de la IP del
   anfitrión al crear el switch virtual): anfitrión *probable* si hay un equipo con esa IP.
5. **Prefijo de MAC** (VMware, KVM, VirtualBox, Xen, Hyper-V, Proxmox, Docker): dice que es virtual,
   no quién lo aloja. Si la sonda corre en un anfitrión con interfaces de virtualización, se le
   atribuye como *probable* (suposición educada); si no, los hipervisores de la misma familia vistos
   en la red quedan como *posibles anfitriones*.
"""

from __future__ import annotations

import json
import socket
import subprocess
from dataclasses import dataclass

from .models import Asset
from .netutil import normalize_mac

# Prefijo de MAC → (plataforma, tipo). Docker actual asigna MACs privadas aleatorias (no 02:42) a
# contenedores en macvlan; los de red puente conservan 02:42:<ip>.
MAC_PREFIXES: list[tuple[str, str, str]] = [
    ("02:42:", "docker", "container"),
    ("52:54:00:", "kvm", "vm"),
    ("bc:24:11:", "proxmox", "vm"),
    ("00:16:3e:", "xen", "vm"),
    ("08:00:27:", "virtualbox", "vm"),
    ("00:50:56:", "vmware", "vm"),
    ("00:0c:29:", "vmware", "vm"),
    ("00:05:69:", "vmware", "vm"),
    ("00:1c:14:", "vmware", "vm"),
    ("00:15:5d:", "hyperv", "vm"),
    ("00:1c:42:", "parallels", "vm"),
]

PLATFORM_LABELS = {
    "docker": "Docker", "podman": "Podman", "lxc": "LXC/LXD", "kubernetes": "Kubernetes (CNI)",
    "kvm": "KVM/QEMU", "proxmox": "Proxmox VE", "xen": "Xen", "virtualbox": "VirtualBox", "vmware": "VMware",
    "hyperv": "Hyper-V", "parallels": "Parallels", "": "",
}
KIND_LABELS = {"container": "contenedor", "vm": "máquina virtual"}

# Interfaces de un anfitrión (IF-MIB ifDescr, `ip link`) → (tipo de invitado, plataforma)
CONTAINER_IFACES: list[tuple[str, str]] = [
    ("docker", "docker"), ("br-", "docker"), ("veth", "docker"), ("podman", "podman"), ("cni", "kubernetes"),
    ("flannel", "kubernetes"), ("cali", "kubernetes"), ("kube", "kubernetes"), ("lxcbr", "lxc"), ("lxdbr", "lxc"),
]
VM_IFACES: list[tuple[str, str]] = [
    ("vmbr", "proxmox"), ("fwbr", "proxmox"), ("fwpr", "proxmox"), ("fwln", "proxmox"), ("virbr", "kvm"),
    ("vnet", "kvm"), ("tap", "kvm"), ("vmnet", "vmware"), ("xenbr", "xen"), ("vif", "xen"),
]
# Puertos que delatan a un anfitrión
HOST_PORTS = {2179: ("hyperv", "vm"), 8006: ("proxmox", "vm"), 902: ("vmware", "vm"), 2375: ("docker", "container"),
              2376: ("docker", "container")}


def label(virtual: dict | None) -> str:
    """«máquina virtual VMware», «contenedor Docker», ''."""
    v = virtual or {}
    if not v.get("kind"):
        return ""
    return " ".join(x for x in (KIND_LABELS.get(v["kind"], v["kind"]), PLATFORM_LABELS.get(v.get("platform", ""), v.get("platform", ""))) if x)


def host_label(virtual: dict | None) -> str:
    v = virtual or {}
    return v.get("host_name") or v.get("host_ip") or ""


def from_mac(mac: str) -> dict | None:
    mac = normalize_mac(mac)
    for prefix, platform, kind in MAC_PREFIXES:
        if mac.startswith(prefix):
            return {"kind": kind, "platform": platform, "reach": "network", "confidence": "",
                    "evidence": f"prefijo de MAC {prefix.rstrip(':')} ({PLATFORM_LABELS[platform]})"}
    return None


def probe_guest(iface: str) -> dict:
    """Invitado visto por una red virtual de la propia sonda: el anfitrión es este equipo."""
    kind = interface_kind(iface) or ("container", "")
    return {"kind": kind[0], "platform": kind[1], "host": "probe", "reach": "host", "confidence": "alta",
            "evidence": f"red virtual {iface} de la sonda"}


def interface_kind(name: str) -> tuple[str, str] | None:
    """(tipo de invitado, plataforma) si la interfaz es de virtualización; None si es física."""
    n = (name or "").lower()
    for prefix, platform in VM_IFACES:
        if n.startswith(prefix):
            return "vm", platform
    for prefix, platform in CONTAINER_IFACES:
        if n.startswith(prefix):
            return "container", platform
    return None


def hyperv_host_suffix(mac: str) -> tuple[int, int] | None:
    """Últimos dos octetos de la IP del anfitrión Hyper-V codificados en una MAC dinámica 00:15:5d."""
    mac = normalize_mac(mac)
    if not mac.startswith("00:15:5d:"):
        return None
    parts = mac.split(":")
    return int(parts[3], 16), int(parts[4], 16)


# --- el equipo de la sonda como anfitrión -------------------------------------------------------

@dataclass
class LocalHosting:
    interfaces: dict[str, tuple[str, str]]  # interfaz virtual → (tipo, plataforma)
    fdb: dict[str, str]  # MAC aprendida en un puerto virtual de un puente → interfaz (vnet3, veth…)

    @property
    def hosts_vms(self) -> bool:
        return any(kind == "vm" for kind, _ in self.interfaces.values())

    @property
    def hosts_containers(self) -> bool:
        return any(kind == "container" for kind, _ in self.interfaces.values())

    def platform_for(self, kind: str) -> str:
        return next((p for k, p in self.interfaces.values() if k == kind), "")


def _run_json(args: list[str]) -> list:
    try:
        out = subprocess.run(args, capture_output=True, text=True, check=True, timeout=5).stdout
        return json.loads(out or "[]")
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        return []


def local_hosting() -> LocalHosting:
    """Interfaces de virtualización del equipo de la sonda y MACs que cuelgan de sus puentes."""
    interfaces = {}
    for link in _run_json(["ip", "-j", "link", "show"]):
        name = link.get("ifname", "")
        if kind := interface_kind(name):
            interfaces[name] = kind
    fdb = {}
    if interfaces:
        for entry in _run_json(["bridge", "-j", "fdb", "show"]):
            iface, mac = entry.get("ifname", ""), normalize_mac(entry.get("mac", ""))
            # Solo lo aprendido en puertos de invitados (vnet/tap/veth): ni la MAC del propio puente ni
            # las entradas permanentes (la del puerto mismo), ni multicast
            if (mac and iface in interfaces and entry.get("state") != "permanent" and "self" not in (entry.get("flags") or [])
                    and not int(mac[:2], 16) & 0x01
                    and not iface.startswith(("docker", "br-", "virbr", "vmbr", "lxcbr", "lxdbr", "xenbr", "cni", "podman"))):
                fdb[mac] = iface
    return LocalHosting(interfaces, fdb)


# --- relación invitado ↔ anfitrión sobre los activos ya conciliados ------------------------------

def _ip_tuple(ip: str) -> tuple[int, ...]:
    try:
        return tuple(int(x) for x in ip.split("."))
    except ValueError:
        return ()


def _is_hypervisor_of(asset: Asset, platform: str) -> bool:
    ports = set(asset.open_ports)
    snmp = asset.attributes.get("snmp") or {}
    text = " ".join([asset.os, asset.model, snmp.get("sys_descr", "")]).lower()
    hosting = asset.attributes.get("hosting") or {}
    if platform == "vmware":
        return 902 in ports or "6876." in snmp.get("sys_object_id", "") or "esxi" in text or bool(hosting.get("vms"))
    if platform == "hyperv":
        return 2179 in ports or "hyper-v" in text
    if platform in ("kvm", "proxmox"):
        return 8006 in ports or "proxmox" in text or any(p in ("kvm", "proxmox") for p in (hosting.get("vm_platforms") or []))
    return asset.device_type == "hypervisor"


def annotate(assets: list[Asset], local: LocalHosting | None = None, probe_name: str = "") -> None:
    """Completa `attributes["virtual"]` de los invitados (anfitrión resuelto a un activo) y
    `attributes["guests"]` de los anfitriones. Se recalcula entero en cada escaneo."""
    local = local or LocalHosting({}, {})
    probe_name = probe_name or socket.gethostname()
    by_id = {a.id: a for a in assets}
    by_ip: dict[str, Asset] = {}
    by_mac: dict[str, Asset] = {}
    for a in assets:
        if guest_scope_of(a):
            continue  # la IP de un contenedor NAT no es de la red
        for ip in a.ips:
            by_ip.setdefault(ip, a)
        for mac in a.macs:
            by_mac.setdefault(mac, a)
    probe = next((a for a in assets if a.attributes.get("is_probe")), None)

    for a in assets:
        v = a.attributes.get("virtual")
        if not v:
            if mac_hint := next((from_mac(m) for m in a.macs if from_mac(m)), None):
                v = mac_hint
            elif a.attributes.get("virtual_net"):
                kind = interface_kind(a.attributes["virtual_net"]) or ("container", "")
                v = {"kind": kind[0], "platform": kind[1], "reach": "host", "confidence": "",
                     "evidence": f"red virtual {a.attributes['virtual_net']} de la sonda"}
            else:
                continue
        v = dict(v)
        # 1-2. Anfitrión por evidencia directa (SNMP): se resuelve a un activo
        if v.get("host") == "probe" or a.attributes.get("virtual_net") or any(m in local.fdb for m in a.macs):
            v.update(host_ip=(probe.ips[0] if probe and probe.ips else v.get("host_ip", "")),
                     host_name=(probe.hostname if probe and probe.hostname else probe_name), confidence="alta")
            if iface := next((local.fdb[m] for m in a.macs if m in local.fdb), ""):
                v["evidence"] = f"cuelga del puerto {iface} de un puente de la sonda"
            v.pop("host", None)
        if v.get("host_ip") and not v.get("host_name"):
            host = by_ip.get(v["host_ip"])
            if host:
                v["host_name"] = host.hostname or ""
        if not v.get("host_ip") and not v.get("host_name"):
            _guess_host(a, v, assets, by_ip, local, probe, probe_name)
        host = by_ip.get(v.get("host_ip", "")) if v.get("host_ip") else None
        if host is None and v.get("host_name"):
            host = next((h for h in assets if h.hostname and h.hostname.split(".")[0].lower() == v["host_name"].split(".")[0].lower()), None)
        if host is None and v.get("host_id") in by_id:
            host = by_id[v["host_id"]]
        if host is not None and host.id != a.id:
            v["host_id"] = host.id
            v.setdefault("host_name", host.hostname)
            if not v.get("host_ip") and host.ips:
                v["host_ip"] = host.ips[0]
        else:
            v.pop("host_id", None)
        a.attributes["virtual"] = v

    # Anfitriones: lista de invitados (se reconstruye entera)
    for a in assets:
        a.attributes.pop("guests", None)
    for a in assets:
        v = a.attributes.get("virtual") or {}
        host = by_id.get(v.get("host_id", ""))
        if host is None:
            continue
        guests = host.attributes.setdefault("guests", [])
        guests.append({"id": a.id, "name": a.hostname or v.get("name", ""), "ip": a.ips[0] if a.ips else "",
                       "kind": v.get("kind", ""), "platform": v.get("platform", ""), "confidence": v.get("confidence", "")})
    for a in assets:
        if "guests" in a.attributes:
            a.attributes["guests"] = sorted(a.attributes["guests"], key=lambda g: _ip_tuple(g["ip"]))[:200]


def _guess_host(asset: Asset, v: dict, assets: list[Asset], by_ip: dict[str, Asset], local: LocalHosting,
                probe: Asset | None, probe_name: str) -> None:
    """Anfitrión probable cuando no hay evidencia directa."""
    platform = v.get("platform", "")
    # 4. Hyper-V: la MAC dinámica lleva los últimos dos octetos de la IP del anfitrión
    for mac in asset.macs:
        if suffix := hyperv_host_suffix(mac):
            for ip, cand in by_ip.items():
                if cand.id != asset.id and _ip_tuple(ip)[2:] == suffix and (2179 in cand.open_ports or
                        cand.attributes.get("os_family") == "windows" or cand.device_type in ("server", "hypervisor")):
                    v.update(host_ip=ip, host_name=cand.hostname, confidence="media",
                             evidence=f"MAC dinámica de Hyper-V derivada de la IP {ip}")
                    return
    # 3/5. La sonda corre en un anfitrión de ese tipo: suposición educada
    kind = v.get("kind", "")
    if (kind == "vm" and local.hosts_vms) or (kind == "container" and local.hosts_containers):
        v.update(host_ip=(probe.ips[0] if probe and probe.ips else ""),
                 host_name=(probe.hostname if probe and probe.hostname else probe_name), confidence="media",
                 evidence=f"la sonda corre en un anfitrión con interfaces {', '.join(sorted(local.interfaces)[:4])}")
        if platform and not v.get("platform"):
            v["platform"] = platform
        return
    # Hipervisores de la misma familia vistos en la red: posibles anfitriones
    candidates = [h for h in assets if h.id != asset.id and not (h.attributes.get("virtual") or {}).get("kind")
                  and _is_hypervisor_of(h, platform)]
    if candidates:
        v["host_candidates"] = [{"id": h.id, "name": h.hostname or (h.ips[0] if h.ips else "")} for h in candidates[:6]]
    else:
        v.pop("host_candidates", None)


def guest_scope_of(asset: Asset) -> str:
    v = asset.attributes.get("virtual") or {}
    return (v.get("host_name") or v.get("host_ip") or "") if v.get("reach") == "host" else ""
