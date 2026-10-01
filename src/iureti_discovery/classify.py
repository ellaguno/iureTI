"""Clasificación del tipo de equipo por reglas con puntaje."""

from __future__ import annotations

import re
from collections import defaultdict

from .mdns import MODEL_TXT_KEYS, hint_for, txt_value
from .models import DEVICE_TYPES, Asset
from .netutil import is_locally_administered

# Enterprise OID (1.3.6.1.4.1.<n>) → (fabricante, tipo probable o None)
ENTERPRISES: dict[int, tuple[str, str | None]] = {
    9: ("Cisco", None),
    11: ("HP", None),
    171: ("D-Link", "switch"),
    253: ("Xerox", "printer"),
    311: ("Microsoft", None),
    318: ("APC", "ups"),
    367: ("Ricoh", "printer"),
    534: ("Eaton", "ups"),
    641: ("Lexmark", "printer"),
    674: ("Dell", None),
    890: ("Zyxel", None),
    1248: ("Epson", "printer"),
    1347: ("Kyocera", "printer"),
    1602: ("Canon", "printer"),
    1916: ("Extreme Networks", "switch"),
    2011: ("Huawei", None),
    2435: ("Brother", "printer"),
    2636: ("Juniper", None),
    3375: ("F5", "router"),
    4413: ("Broadcom (EdgeSwitch)", "switch"),
    4526: ("Netgear", "switch"),
    6486: ("Alcatel-Lucent", "switch"),
    6574: ("Synology", "nas"),
    6876: ("VMware", "hypervisor"),
    8072: ("Net-SNMP", None),
    11863: ("TP-Link", None),
    12325: ("pfSense/FreeBSD", "firewall"),
    12356: ("Fortinet", "firewall"),
    14823: ("Aruba", "access_point"),
    14988: ("MikroTik", "router"),
    24681: ("QNAP", "nas"),
    25053: ("Ruckus", "access_point"),
    25461: ("Palo Alto Networks", "firewall"),
    25506: ("HPE/H3C", "switch"),
    29671: ("Cisco Meraki", None),
    30065: ("Arista", "switch"),
    41112: ("Ubiquiti", None),
}

# (patrón, tipo, peso) aplicados a sysDescr, modelo y fabricante
TEXT_RULES: list[tuple[str, str, int]] = [
    (r"laserjet|officejet|deskjet|pagewide|designjet|imagerunner|imageclass|bizhub|workcentre|versalink|altalink|"
     r"ecosys|taskalfa|\bmfc-|\bhl-\w|\bdcp-|workforce|ecotank|\bprinter\b|impresora|jetdirect", "printer", 6),
    (r"fortigate|fortios|pan-os|palo alto|\basa\b|adaptive security|firepower|sonicwall|sonicos|pfsense|opnsense|"
     r"sophos|watchguard|fireware|check ?point|gaia", "firewall", 7),
    (r"access point|\bunifi ap\b|\buap\b|\bu6-|\bu7-|aironet|\bair-?ap|arubaos.*\bap\b|instant ap|\beap\d|ruckus|"
     r"meraki mr|\bcap ac\b|wireless ap", "access_point", 7),
    (r"\bswitch\b|catalyst|\bc9[235]00|\bc3[678]50|\bc2960|nexus|procurve|arubaos-cx|comware|edgeswitch|\busw\b|"
     r"\bcbs\d|\bsg\d{3}|powerconnect|os10|dell networking|cloud engine|\bs\d{4}-", "switch", 6),
    (r"\brouter\b|routeros|edgeos|edgerouter|\bisr\d|\basr\d|junos.*\bmx|\bcisco ios software\b", "router", 4),
    (r"\bups\b|smart-ups|symmetra|powerware|network management card|eaton|\bnmc\b", "ups", 7),
    (r"synology|diskstation|qnap|\bqts\b|truenas|freenas|\bnas\b|readynas|terastation", "nas", 7),
    (r"esxi|vmkernel|vmware esx|proxmox|hyper-v", "hypervisor", 8),
    (r"hikvision|dahua|axis .*camera|ip camera|network camera|\bnvr\b|\bdvr\b", "camera", 7),
    (r"yealink|polycom|grandstream|cisco ip phone|\bsip-t\d|avaya", "phone", 7),
    (r"windows server|microsoft windows server", "server", 7),
    (r"windows 1[01]|windows 7|windows 8|microsoft windows", "workstation", 3),
]

VENDOR_HINTS: list[tuple[str, str, int]] = [
    (r"ubiquiti", "access_point", 2),
    (r"aruba|ruckus|cambium", "access_point", 3),
    (r"brother|epson|lexmark|kyocera|ricoh|xerox|canon|konica|sharp|oki", "printer", 3),
    (r"fortinet|palo alto|sonicwall|watchguard|sophos", "firewall", 4),
    (r"synology|qnap", "nas", 4),
    (r"hikvision|dahua|axis comm", "camera", 4),
    (r"yealink|polycom|grandstream", "phone", 4),
    (r"american power|apc|eaton|vertiv|liebert", "ups", 3),
    (r"espressif|tuya|shelly|sonoff|raspberry|amazon|google|sonos|roku|xiaomi", "iot", 2),
    (r"vmware", "server", 2),
]

HOSTNAME_HINTS: list[tuple[str, str, int]] = [
    (r"^(android|pixel|galaxy|iphone|ipad|redmi|moto|oneplus|xiaomi|huawei-p|honor)", "mobile", 5),
    (r"^(macbook)", "laptop", 4),
    (r"^(imac|mac-?mini|mac-?pro|mac-?studio)", "workstation", 4),
    (r"^(chromecast|appletv|apple-tv|roku|firetv|sonos|google-home|nest|echo-)", "iot", 4),
    (r"^(sw|swi|switch)[-_\d]|[-_](sw|switch)\d*$", "switch", 3),
    (r"^(fw|firewall)[-_\d]", "firewall", 3),
    (r"^(ap|wap)[-_\d]", "access_point", 3),
    (r"^(rt|rtr|router|gw)[-_\d]", "router", 2),
    (r"^(srv|svr|server|dc\d|sql|esx|pve|hv)", "server", 3),
    (r"^(prn|print|imp)[-_\d]", "printer", 3),
    # Solo como palabra del nombre (lap-…, …-nb, lt07, LAPTOP-…): «lap» dentro de otra palabra no cuenta
    (r"(^|[-_])(lap|lt|ltp|nb)([-_\d]|$)|laptop|notebook|portatil", "laptop", 3),
    (r"^(pc|ws|desk|dsk|wks)[-_\d]", "workstation", 3),
    (r"^(ups)[-_\d]", "ups", 3),
    (r"^(nas)[-_\d]", "nas", 3),
    (r"^(cam|ipcam)[-_\d]", "camera", 3),
]


# Líneas de portátiles; se buscan solo en campos de modelo (no en títulos web: «Latitude», «Notebook» de Jupyter…)
LAPTOP_MODELS = re.compile(
    r"\b(thinkpad|thinkbook|latitude|elitebook|probook|zbook|zenbook|vivobook|ideapad|chromebook|macbook\w*|travelmate|"
    r"surface (laptop|book)|xps 1[3-7]|inspiron 1[3-7]|yoga|spectre|(envy|pavilion) x360|notebook|laptop|port[aá]til)\b")
ALL_IN_ONE = re.compile(r"\b(aio|all-in-one|todo en uno)\b")


def laptop_model(asset: Asset) -> str:
    """Modelo que delata un portátil (SNMP, UPnP, mDNS o candidato HTTP), o ''."""
    snmp = asset.attributes.get("snmp") or {}
    upnp = asset.attributes.get("upnp") or {}
    http = asset.attributes.get("http") or {}
    fields = [asset.model, snmp.get("sys_descr", ""), upnp.get("modelName", ""), upnp.get("modelDescription", ""),
              upnp.get("friendlyName", ""), txt_value(asset.attributes.get("mdns") or {}, *MODEL_TXT_KEYS),
              *http.get("model_candidates", [])]
    for field in fields:
        if field and (m := LAPTOP_MODELS.search(field.lower())) and not ALL_IN_ONE.search(field.lower()):
            return field.strip() if len(field) <= 60 else m.group(0)
    return ""


def enterprise_number(sys_object_id: str) -> int | None:
    m = re.match(r"^\.?1\.3\.6\.1\.4\.1\.(\d+)", sys_object_id or "")
    return int(m.group(1)) if m else None


def port_scores(ports: set[int], scores: dict[str, float], reasons: list[str]) -> None:
    def add(kind: str, pts: float, why: str) -> None:
        scores[kind] += pts
        reasons.append(why)

    windows = bool(ports & {135, 139, 445}) or 3389 in ports
    if ports & {9100, 515, 631}:
        add("printer", 5, "puertos de impresión (9100/515/631)")
    if 8006 in ports:
        add("hypervisor", 6, "Proxmox (8006)")
    if 902 in ports:
        add("hypervisor", 5, "VMware ESXi (902)")
    if 554 in ports:
        add("camera", 3, "RTSP (554)")
    if 5060 in ports:
        add("phone", 3, "SIP (5060)")
    if windows:
        server_ports = ports & {53, 88, 389, 636, 1433, 3268, 80, 443, 5985}
        if ports & {88, 389, 3268}:
            add("server", 6, "controlador de dominio (Kerberos/LDAP)")
        elif len(server_ports) >= 2 or 1433 in ports:
            add("server", 3, "Windows con servicios de servidor")
        else:
            add("workstation", 4, "Windows (RPC/SMB/RDP)")
    elif 22 in ports:
        if ports & {3306, 5432, 1433, 27017, 6379, 25, 53, 389, 2049, 111}:
            add("server", 4, "SSH + servicios de servidor")
        elif ports & {80, 443, 8080, 8443}:
            add("server", 2, "SSH + web")
        elif 23 in ports:
            add("switch", 2, "SSH + Telnet (equipo de red)")
        else:
            add("server", 1, "SSH")
    if 23 in ports and not windows:
        add("switch", 1, "Telnet")


# Prefijos de MAC de máquinas virtuales (y Docker antiguo, 02:42:…). Docker actual asigna MACs privadas
# aleatorias: esos contenedores se reconocen por la red virtual de la sonda (atributo virtual_net).
VIRTUAL_MAC_PREFIXES = [
    ("02:42:", "contenedor Docker"),
    ("52:54:00:", "máquina virtual KVM/QEMU"),
    ("00:16:3e:", "máquina virtual Xen"),
    ("08:00:27:", "máquina virtual VirtualBox"),
    ("00:50:56:", "máquina virtual VMware"),
    ("00:0c:29:", "máquina virtual VMware"),
    ("00:05:69:", "máquina virtual VMware"),
    ("00:15:5d:", "máquina virtual Hyper-V"),
]


def virtual_kind(macs: list[str]) -> str:
    for mac in macs:
        for prefix, label in VIRTUAL_MAC_PREFIXES:
            if mac.lower().startswith(prefix):
                return label
    return ""


UPNP_DEVICE_TYPES = [
    ("internetgatewaydevice", "router", 5),
    ("wlanaccesspoint", "access_point", 5),
    ("printer", "printer", 6),
    ("mediarenderer", "iot", 3),
    ("mediaserver", "nas", 2),
]
ANNOUNCED_TYPES = {"phone": "mobile", "tablet": "mobile", "laptop": "laptop", "desktop": "workstation", "tv": "iot"}


def local_source_scores(asset: Asset, scores: dict[str, float], reasons: list[str]) -> None:
    def add(kind: str, pts: float, why: str) -> None:
        scores[kind] += pts
        reasons.append(why)

    mdns = asset.attributes.get("mdns") or {}
    for service in mdns.get("services", []):
        if (hint := hint_for(service)) and hint[1]:
            label, kind = hint
            add(kind, 4, f"anuncia {label} (mDNS)")
    if (announced := txt_value(mdns, "type").lower()) in ANNOUNCED_TYPES:
        add(ANNOUNCED_TYPES[announced], 6, f"se anuncia como «{announced}» (mDNS)")

    device_type = ((asset.attributes.get("upnp") or {}).get("deviceType") or "").lower()
    for needle, kind, pts in UPNP_DEVICE_TYPES:
        if needle in device_type:
            add(kind, pts, f"UPnP {device_type.split(':')[-2] if ':' in device_type else device_type}")

    found = asset.attributes.get("enrichment") or {}
    if found.get("identified") and found.get("device_type") in DEVICE_TYPES and found.get("device_type") != "unknown":
        weight = {"alta": 8, "media": 5}.get(found.get("confidence"), 0)
        if weight:
            add(found["device_type"], weight, f"identificado en internet como {found.get('product_name') or found.get('model')}")

    if chassis := asset.attributes.get("chassis"):
        add(chassis, 8, "este equipo (la sonda): tipo de chasis DMI")

    ports = set(asset.open_ports)
    if 62078 in ports:
        add("mobile", 6, "servicio de sincronización de iPhone/iPad (62078)")
    if asset.attributes.get("os_family") == "windows" and not ports & {88, 389, 3268}:
        add("workstation", 1, "TTL de Windows")

    if iface := asset.attributes.get("virtual_net"):
        add("server", 3, f"contenedor o VM de la sonda (red virtual {iface})")
        return  # una MAC privada de contenedor no sugiere un celular
    if virtual := virtual_kind(asset.macs):
        add("server", 3, f"{virtual} (prefijo de MAC)")
        return

    private_mac = any(is_locally_administered(m) for m in asset.macs)
    if private_mac and not ports and not scores:
        add("mobile", 2, "MAC privada y sin servicios abiertos: probable celular o tablet")


def classify(asset: Asset) -> tuple[str, float, list[str]]:
    scores: dict[str, float] = defaultdict(float)
    reasons: list[str] = []
    snmp = asset.attributes.get("snmp") or {}

    ent = enterprise_number(snmp.get("sys_object_id", ""))
    if ent is not None and ent in ENTERPRISES:
        name, kind = ENTERPRISES[ent]
        if kind:
            scores[kind] += 4
            reasons.append(f"sysObjectID de {name}")

    upnp = asset.attributes.get("upnp") or {}
    http = asset.attributes.get("http") or {}
    text = " ".join([
        snmp.get("sys_descr", ""), asset.model, asset.os,
        upnp.get("modelName", ""), upnp.get("modelDescription", ""), upnp.get("friendlyName", ""),
        http.get("title", ""), http.get("realm", ""), http.get("server", ""),
    ]).lower()
    for pattern, kind, weight in TEXT_RULES:
        if text.strip() and re.search(pattern, text):
            scores[kind] += weight
            reasons.append(f"descripción/modelo sugiere {kind}")

    vendor = asset.vendor.lower()
    for pattern, kind, weight in VENDOR_HINTS:
        if vendor and re.search(pattern, vendor):
            scores[kind] += weight
            reasons.append(f"fabricante {asset.vendor}")

    hostname = asset.hostname.split(".")[0].lower()
    for pattern, kind, weight in HOSTNAME_HINTS:
        if hostname and re.search(pattern, hostname):
            scores[kind] += weight
            reasons.append(f"nombre '{hostname}'")

    if model := laptop_model(asset):
        scores["laptop"] += 3
        reasons.append(f"modelo de portátil ({model})")

    port_scores(set(asset.open_ports), scores, reasons)
    local_source_scores(asset, scores, reasons)

    # Puertos de Windows, TTL y SO dicen «equipo de usuario», no su forma: con indicios de portátil, ese puntaje es
    # de portátil. No aplica si el chasis DMI o el propio equipo (mDNS) ya dicen escritorio; servidores no se tocan.
    announced = txt_value(asset.attributes.get("mdns") or {}, "type").lower()
    if scores.get("laptop") and scores.get("workstation") and not asset.attributes.get("chassis") and announced != "desktop":
        scores["laptop"] += scores.pop("workstation")
        reasons.append("indicios de portátil: equipo de usuario portátil, no de escritorio")

    if asset.attributes.get("is_gateway"):
        # Suele ser router o firewall; si ya hay indicios de firewall, se respetan
        scores["router"] += 5
        reasons.append("puerta de enlace de la red")
    ports = set(asset.open_ports)
    if 53 in ports and not ports & {135, 139, 445, 22}:
        scores["router"] += 1
        reasons.append("DNS (53) sin servicios de servidor")
    if asset.attributes.get("is_probe"):
        reasons.append("este equipo (la sonda)")

    # Un equipo que responde SNMP con sysDescr genérico de Linux suele ser servidor/appliance
    if snmp and not scores and "linux" in text:
        scores["server"] += 1
        reasons.append("SNMP Linux")

    if not scores:
        return "unknown", 0.0, []
    kind, top = max(scores.items(), key=lambda kv: kv[1])
    runner_up = max((v for k, v in scores.items() if k != kind), default=0.0)
    confidence = min(1.0, top / 10) * (1 - 0.5 * runner_up / top)
    return kind, round(confidence, 2), list(dict.fromkeys(reasons))
