"""Consultas SNMP de solo lectura (v2c y v3)."""

from __future__ import annotations

from dataclasses import dataclass

from pysnmp.hlapi.v3arch.asyncio import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    UsmUserData,
    get_cmd,
    next_cmd,
    usmAesCfb128Protocol,
    usmAesCfb256Protocol,
    usmDESPrivProtocol,
    usmHMACMD5AuthProtocol,
    usmHMACSHAAuthProtocol,
    usmHMAC192SHA256AuthProtocol,
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
        try:
            info = await query(ip, cred, timeout=timeout)
        except Exception:
            info = None
        if info:
            return info
    return None
