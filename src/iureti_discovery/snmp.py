"""Consultas SNMP de solo lectura (v2c y v3)."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

from pysnmp.hlapi.v3arch.asyncio import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    UsmUserData,
    bulk_cmd,
    get_cmd,
    next_cmd,
    usmAesCfb128Protocol,
    usmAesCfb256Protocol,
    usmDESPrivProtocol,
    usmHMAC192SHA256AuthProtocol,
    usmHMACMD5AuthProtocol,
    usmHMACSHAAuthProtocol,
    usmNoAuthProtocol,
    usmNoPrivProtocol,
)

from .models import SnmpInfo

SYS_DESCR = "1.3.6.1.2.1.1.1.0"
SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"
SYS_CONTACT = "1.3.6.1.2.1.1.4.0"
SYS_NAME = "1.3.6.1.2.1.1.5.0"
SYS_LOCATION = "1.3.6.1.2.1.1.6.0"
ENT_PHYSICAL_CLASS = "1.3.6.1.2.1.47.1.1.1.1.5"
ENT_PHYSICAL_SERIAL = "1.3.6.1.2.1.47.1.1.1.1.11"
ENT_PHYSICAL_MODEL = "1.3.6.1.2.1.47.1.1.1.1.13"
PRT_SERIAL = "1.3.6.1.2.1.43.5.1.1.17.1"  # Printer-MIB prtGeneralSerialNumber
HR_DEVICE_DESCR_PRINTER = "1.3.6.1.2.1.25.3.2.1.3.1"
ENT_CLASS_CHASSIS = 3
# Anfitriones: interfaces (IF-MIB), tabla ARP (IP-MIB) y VMs de ESXi (VMWARE-VMINFO-MIB)
IF_DESCR = "1.3.6.1.2.1.2.2.1.2"
IP_NET_TO_MEDIA_PHYS = "1.3.6.1.2.1.4.22.1.2"  # índice: <ifIndex>.<ip>
VMWARE_ENTERPRISE = 6876
VMW_VM_DISPLAY_NAME = "1.3.6.1.4.1.6876.2.1.1.2"  # índice: vmIdx
VMW_VM_MAC = "1.3.6.1.4.1.6876.2.4.1.7"  # índice: vmIdx.netIdx

AUTH_PROTOCOLS = {
    "none": usmNoAuthProtocol,
    "MD5": usmHMACMD5AuthProtocol,
    "SHA": usmHMACSHAAuthProtocol,
    "SHA256": usmHMAC192SHA256AuthProtocol,
}
PRIV_PROTOCOLS = {
    "none": usmNoPrivProtocol,
    "DES": usmDESPrivProtocol,
    "AES": usmAesCfb128Protocol,
    "AES256": usmAesCfb256Protocol,
}


@dataclass
class SnmpCredential:
    name: str
    version: str = "2c"  # "2c" | "3"
    community: str = "public"
    user: str = ""
    auth_protocol: str = "SHA"
    auth_key: str = ""
    priv_protocol: str = "AES"
    priv_key: str = ""
    networks: list = field(default_factory=list)  # subredes donde probar esta credencial; vacío = todas

    def applies_to(self, ip: str) -> bool:
        """Una community SNMP v2c viaja en claro: restringirla a su VLAN de gestión evita filtrarla
        a toda la red (C1). Sin subredes configuradas, se prueba en cualquier objetivo (compatibilidad)."""
        if not self.networks:
            return True
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        for cidr in self.networks:
            try:
                if addr in ipaddress.ip_network(str(cidr).strip(), strict=False):
                    return True
            except ValueError:
                continue
        return False

    def auth_data(self):
        if self.version == "3":
            auth = AUTH_PROTOCOLS[self.auth_protocol if self.auth_key else "none"]
            priv = PRIV_PROTOCOLS[self.priv_protocol if self.priv_key else "none"]
            return UsmUserData(
                self.user,
                authKey=self.auth_key or None,
                privKey=self.priv_key or None,
                authProtocol=auth,
                privProtocol=priv,
            )
        return CommunityData(self.community, mpModel=1)

    def public_dict(self) -> dict:
        """Representación sin secretos."""
        return {"name": self.name, "version": self.version, "user": self.user}


_ENGINE: SnmpEngine | None = None


def _engine() -> SnmpEngine:
    global _ENGINE
    if _ENGINE is None:
        _ENGINE = SnmpEngine()
    return _ENGINE


def _clean(value) -> str:
    if value is None:
        return ""
    cls = value.__class__.__name__
    if cls in ("NoSuchObject", "NoSuchInstance", "EndOfMibView", "Null"):
        return ""
    text = value.prettyPrint() if hasattr(value, "prettyPrint") else str(value)
    return text.replace("\x00", "").strip()


async def _get(target, auth, oids: list[str]) -> dict[str, str] | None:
    err_ind, err_status, _, var_binds = await get_cmd(
        _engine(), auth, target, ContextData(), *(ObjectType(ObjectIdentity(o)) for o in oids)
    )
    if err_ind or err_status:
        return None
    return {str(name): _clean(val) for name, val in var_binds}


async def _walk_column(target, auth, oid: str, max_rows: int = 64) -> dict[str, str]:
    """Recorre una columna de tabla y devuelve {índice: valor}."""
    rows: dict[str, str] = {}
    current = oid
    for _ in range(max_rows):
        err_ind, err_status, _, var_binds = await next_cmd(
            _engine(), auth, target, ContextData(), ObjectType(ObjectIdentity(current)), lexicographicMode=False
        )
        if err_ind or err_status or not var_binds:
            break
        name, val = var_binds[0]
        name = str(name)
        if not name.startswith(oid + "."):
            break
        rows[name[len(oid) + 1 :]] = _clean(val)
        current = name
    return rows


def _mac(value) -> str:
    """OctetString de 6 bytes (PhysAddress) → aa:bb:cc:dd:ee:ff; '' si no es una MAC."""
    if value is None:
        return ""
    raw = value.asOctets() if hasattr(value, "asOctets") else None
    if raw is not None:
        return ":".join(f"{b:02x}" for b in raw) if len(raw) == 6 else ""
    text = str(value)
    return ":".join(text[i:i + 2] for i in range(2, 14, 2)).lower() if text.startswith("0x") and len(text) == 14 else ""


async def _walk_bulk(target, auth, oid: str, max_rows: int = 512, raw: bool = False) -> dict:
    """Recorre una columna con GETBULK (una petición por cada 25 filas). {índice: valor}."""
    rows: dict = {}
    current = oid
    while len(rows) < max_rows:
        err_ind, err_status, _, var_binds = await bulk_cmd(
            _engine(), auth, target, ContextData(), 0, 25, ObjectType(ObjectIdentity(current)), lexicographicMode=False
        )
        if err_ind or err_status or not var_binds:
            break
        done = False
        for name, val in var_binds:
            name = str(name)
            if not name.startswith(oid + ".") or val.__class__.__name__ == "EndOfMibView":
                done = True
                break
            rows[name[len(oid) + 1:]] = val if raw else _clean(val)
            current = name
        if done or len(var_binds) < 25:
            break
    return rows


async def query_hosting(ip: str, cred: SnmpCredential, sys_object_id: str = "", timeout: float = 1.5) -> dict | None:
    """Qué aloja este equipo, según SNMP.

    {"container_interfaces": [...], "vm_interfaces": [...], "vm_platforms": [...],
     "arp": [{"ip", "mac", "iface", "virtual": bool}], "vms": [{"name", "macs": [...]}]}
    None si no se pudo leer nada. La tabla ARP de un router sirve además para dar MAC a hosts de
    otras subredes (identidad), aunque el equipo no aloje nada.
    """
    from . import virtual

    target = await UdpTransportTarget.create((ip, 161), timeout=timeout, retries=0)
    auth = cred.auth_data()
    try:
        ifaces = await _walk_bulk(target, auth, IF_DESCR, max_rows=256)
    except Exception:
        ifaces = {}
    kinds = {idx: virtual.interface_kind(descr) for idx, descr in ifaces.items()}
    out: dict = {
        "container_interfaces": sorted(d for i, d in ifaces.items() if (kinds[i] or ("",))[0] == "container"),
        "vm_interfaces": sorted(d for i, d in ifaces.items() if (kinds[i] or ("",))[0] == "vm"),
        "vm_platforms": sorted({k[1] for k in kinds.values() if k and k[0] == "vm"}),
        "arp": [], "vms": [],
    }
    try:
        for index, value in (await _walk_bulk(target, auth, IP_NET_TO_MEDIA_PHYS, max_rows=1024, raw=True)).items():
            if_index, _, host_ip = index.partition(".")
            mac = _mac(value)
            if not mac or mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff") or host_ip == ip:
                continue
            kind = kinds.get(if_index)
            out["arp"].append({"ip": host_ip, "mac": mac, "iface": ifaces.get(if_index, ""),
                               "kind": kind[0] if kind else "", "platform": kind[1] if kind else ""})
    except Exception:
        pass
    if re.match(rf"^\.?1\.3\.6\.1\.4\.1\.{VMWARE_ENTERPRISE}\.", sys_object_id or ""):
        try:
            names = await _walk_bulk(target, auth, VMW_VM_DISPLAY_NAME, max_rows=512)
            macs = await _walk_bulk(target, auth, VMW_VM_MAC, max_rows=2048, raw=True)
            vms = {idx: {"name": name, "macs": []} for idx, name in names.items()}
            for index, value in macs.items():
                vm_idx = index.split(".")[0]
                if (mac := _mac(value)) and vm_idx in vms and mac not in vms[vm_idx]["macs"]:
                    vms[vm_idx]["macs"].append(mac)
            out["vms"] = list(vms.values())
        except Exception:
            pass
    if not (ifaces or out["arp"] or out["vms"]):
        return None
    return out


def _pick_chassis(classes: dict[str, str], values: dict[str, str]) -> str:
    for idx, cls in classes.items():
        if cls == str(ENT_CLASS_CHASSIS) and values.get(idx):
            return values[idx]
    return next((v for v in values.values() if v), "")


async def query(ip: str, cred: SnmpCredential, timeout: float = 1.5, retries: int = 0) -> SnmpInfo | None:
    """Devuelve SnmpInfo si el equipo responde con esta credencial; None si no."""
    target = await UdpTransportTarget.create((ip, 161), timeout=timeout, retries=retries)
    auth = cred.auth_data()
    base = await _get(target, auth, [SYS_DESCR, SYS_OBJECT_ID, SYS_NAME, SYS_LOCATION, SYS_CONTACT])
    if not base:
        return None
    info = SnmpInfo(
        sys_descr=base.get(SYS_DESCR, ""),
        sys_object_id=base.get(SYS_OBJECT_ID, ""),
        sys_name=base.get(SYS_NAME, ""),
        sys_location=base.get(SYS_LOCATION, ""),
        sys_contact=base.get(SYS_CONTACT, ""),
        credential=cred.name,
    )
    try:
        classes = await _walk_column(target, auth, ENT_PHYSICAL_CLASS)
        if classes:
            info.serial = _pick_chassis(classes, await _walk_column(target, auth, ENT_PHYSICAL_SERIAL))
            info.model = _pick_chassis(classes, await _walk_column(target, auth, ENT_PHYSICAL_MODEL))
        if not info.serial or not info.model:
            extra = await _get(target, auth, [PRT_SERIAL, HR_DEVICE_DESCR_PRINTER]) or {}
            info.serial = info.serial or extra.get(PRT_SERIAL, "")
            info.model = info.model or extra.get(HR_DEVICE_DESCR_PRINTER, "")
    except Exception:  # los datos opcionales no deben tumbar la consulta básica
        pass
    return info


async def query_any(ip: str, creds: list[SnmpCredential], timeout: float = 1.5) -> SnmpInfo | None:
    for cred in creds:
        if not cred.applies_to(ip):  # no mandar la community a subredes fuera de su alcance (C1)
            continue
        try:
            info = await query(ip, cred, timeout=timeout)
        except Exception:
            info = None
        if info:
            return info
    return None


def credential_named(creds: list[SnmpCredential], name: str) -> SnmpCredential | None:
    return next((c for c in creds if c.name == name), None)
