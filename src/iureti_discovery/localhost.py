"""Datos del propio equipo donde corre la sonda (DMI y /etc/os-release), sin privilegios."""

from __future__ import annotations

from pathlib import Path

DMI = Path("/sys/class/dmi/id")
# SMBIOS chassis type: https://www.dmtf.org/standards/smbios
LAPTOP_CHASSIS = {8, 9, 10, 14, 30, 31, 32}
DESKTOP_CHASSIS = {3, 4, 5, 6, 7, 13, 15, 16, 35, 36}
SERVER_CHASSIS = {17, 23, 25, 28, 29}


def _read(name: str) -> str:
    try:
        value = (DMI / name).read_text().strip()
    except OSError:  # product_serial requiere root
        return ""
    return "" if value.lower() in ("", "none", "default string", "to be filled by o.e.m.", "system product name") else value


def os_name() -> str:
    try:
        for line in Path("/etc/os-release").read_text().splitlines():
            if line.startswith("PRETTY_NAME="):
                return line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    return ""


def describe() -> dict:
    """{"vendor", "model", "serial", "os", "chassis"}; chassis ∈ laptop/workstation/server/''."""
    try:
        chassis = int(_read("chassis_type") or 0)
    except ValueError:
        chassis = 0
    kind = ("laptop" if chassis in LAPTOP_CHASSIS else "workstation" if chassis in DESKTOP_CHASSIS
            else "server" if chassis in SERVER_CHASSIS else "")
    # Lenovo pone el nombre comercial en product_version y el tipo de máquina en product_name
    name, version = _read("product_name"), _read("product_version")
    model = name
    if _read("sys_vendor").upper() == "LENOVO" and version:
        model = f"{version} ({name})" if name else version
    return {"vendor": _read("sys_vendor"), "model": model, "serial": _read("product_serial"),
            "os": os_name(), "chassis": kind}
