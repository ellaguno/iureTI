"""Conciliación de observaciones con activos existentes (deduplicación)."""

from __future__ import annotations

import re
from dataclasses import asdict

from .classify import ENTERPRISES, classify, enterprise_number
from . import localhost, mdns
from .models import Asset, Observation
from .netutil import is_locally_administered, normalize_mac, os_family_from_ttl

# MACs que no identifican a nadie: interfaces sin dirección (GLPI-Agent reporta 00:00:00:00:00:00)
# y broadcast. Misma regla que iurefficient (plugins/iur_inventory/identity.py).
JUNK_MACS = {"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"}

JUNK_SERIALS = {
    "", "0", "00000000", "none", "n/a", "na", "unknown", "default string", "not specified",
    "to be filled by o.e.m.", "system serial number", "0123456789", "123456789", "serial",
}


def normalize_serial(serial: str) -> str:
    s = (serial or "").strip()
    if s.lower() in JUNK_SERIALS or re.fullmatch(r"0+|x+|\.+|-+", s.lower()):
        return ""
    return s.upper()


def normalize_hostname(hostname: str) -> str:
    h = (hostname or "").strip().lower().rstrip(".")
    if not h or h.startswith("_") or re.fullmatch(r"[\d.]+", h):  # PTR = IP o nombre sintético no identifican
        return ""
    return h.split(".")[0]


def identity_keys(serial: str = "", macs: list[str] = (), hostname: str = "") -> list[str]:
    """Claves fuertes en orden de prioridad: serie > MAC universal > hostname."""
    keys = []
    if s := normalize_serial(serial):
        keys.append(f"serial:{s}")
    for mac in macs:
        mac = normalize_mac(mac)
        if mac and mac not in JUNK_MACS and not is_locally_administered(mac):
            keys.append(f"mac:{mac}")
    if h := normalize_hostname(hostname):
        keys.append(f"host:{h}")
    return keys


def asset_keys(asset: Asset) -> list[str]:
    return identity_keys(asset.serial, asset.macs, asset.hostname)


def observed_hostname(obs: Observation) -> str:
    """DNS inverso > sysName SNMP > NetBIOS > nombre mDNS."""
    for name in (obs.hostname, obs.snmp.sys_name if obs.snmp else "",
                 (obs.netbios or {}).get("name", ""), (obs.mdns or {}).get("host", "")):
        if normalize_hostname(name):
            return name
    return ""


def observed_serial(obs: Observation) -> str:
    return normalize_serial(obs.snmp.serial if obs.snmp else "") or normalize_serial((obs.upnp or {}).get("serialNumber", ""))


def observation_keys(obs: Observation) -> list[str]:
    return identity_keys(observed_serial(obs), [obs.mac] if obs.mac else [], observed_hostname(obs))


_GENERIC_MODEL = re.compile(r"\b(series|device|model|igd|gateway|router|unknown)\b", re.I)


def is_generic_model(model: str) -> bool:
    return not model or bool(_GENERIC_MODEL.search(model))


def upnp_model(info: dict) -> str:
    name, number = info.get("modelName", ""), info.get("modelNumber", "")
    if number and not is_generic_model(number) and number not in name:
        return f"{name} {number}".strip()
    return name


def _prepend_unique(items: list, value) -> list:
    if not value:
        return items
    return [value] + [i for i in items if i != value]


PRODUCT_BRANDS = [
    (r"^pixel\b", "Google"), (r"^(galaxy|sm-)", "Samsung"), (r"^(iphone|ipad|macbook|imac)", "Apple"),
    (r"^(redmi|xiaomi|poco)\b", "Xiaomi"), (r"^moto\b", "Motorola"), (r"^oneplus\b", "OnePlus"),
    (r"^(huawei|honor)\b", "Huawei"), (r"^(oppo|reno)\b", "OPPO"), (r"^vivo\b", "vivo"), (r"^nokia\b", "Nokia"),
    (r"^xperia\b", "Sony"), (r"^(thinkpad|ideapad|yoga)\b", "Lenovo"),
]


_PERSONAL = re.compile(r"\b(de|del|of)\b|['’]s\b", re.I)


def product_brand(name: str) -> str:
    """Marca si el nombre parece un producto de fábrica («Pixel 9 Pro»); '' si es personal («iPhone de Juan»)."""
    if _PERSONAL.search(name):
        return ""
    for pattern, brand in PRODUCT_BRANDS:
        if re.search(pattern, name.strip(), re.I):
            return brand
    return ""


class Reconciler:
    def __init__(self, assets: list[Asset]):
        self.assets: dict[str, Asset] = {a.id: a for a in assets}
        self.index: dict[str, str] = {}
        self.ip_index: dict[str, str] = {}
        for a in assets:
            self._index(a)

    def _index(self, asset: Asset) -> None:
        for key in asset_keys(asset):
            self.index.setdefault(key, asset.id)
        for ip in asset.ips:
            self.ip_index[ip] = asset.id

    def _find(self, obs: Observation) -> Asset | None:
        keys = observation_keys(obs)
        for key in keys:
            if key in self.index:
                return self.assets[self.index[key]]
        if obs.ip in self.ip_index:
            candidate = self.assets[self.ip_index[obs.ip]]
            # Observación sin identidad (p.ej. esta vez no hubo ARP): se asume el mismo equipo de esa IP.
            # Observación con identidad nueva: solo "mejora" a un activo que se conocía únicamente por IP.
            if not keys or not asset_keys(candidate):
                return candidate
        return None

    def merge(self, obs: Observation) -> tuple[Asset, bool]:
        """Incorpora la observación. Devuelve (activo, es_nuevo)."""
        asset = self._find(obs)
        is_new = asset is None
        if is_new:
            asset = Asset(first_seen=obs.observed_at)
            self.assets[asset.id] = asset

        # La IP ya no pertenece a otro activo sin identidad (p.ej. DHCP)
        prev_owner = self.ip_index.get(obs.ip)
        if prev_owner and prev_owner != asset.id:
            other = self.assets[prev_owner]
            other.ips = [ip for ip in other.ips if ip != obs.ip]

        asset.ips = _prepend_unique(asset.ips, obs.ip)
        asset.macs = _prepend_unique(asset.macs, normalize_mac(obs.mac))
        snmp = obs.snmp
        if hostname := observed_hostname(obs):
            asset.hostname = hostname
        if obs.vendor:
            asset.vendor = obs.vendor
        asset.open_ports = sorted(set(obs.open_ports))
        asset.sources = sorted(set(asset.sources) | set(obs.sources))
        asset.last_seen = obs.observed_at
        asset.attributes["alive_by"] = obs.alive_by
        for flag in ("is_gateway", "is_probe"):
            if getattr(obs, flag):
                asset.attributes[flag] = True
            else:
                asset.attributes.pop(flag, None)

        if snmp:
            asset.attributes["snmp"] = asdict(snmp)
            asset.serial = normalize_serial(snmp.serial) or asset.serial
            asset.model = snmp.model or asset.model
            asset.os = snmp.sys_descr.splitlines()[0][:200] if snmp.sys_descr else asset.os
            asset.location = snmp.sys_location or asset.location
            ent = enterprise_number(snmp.sys_object_id)
            if ent in ENTERPRISES and (not asset.vendor or asset.vendor.startswith("(")):
                asset.vendor = ENTERPRISES[ent][0]

        self._merge_local_sources(asset, obs)

        if not asset.type_locked:
            asset.device_type, asset.confidence, asset.reasons = classify(asset)

        keys = asset_keys(asset)
        asset.fingerprint = keys[0] if keys else f"ip:{obs.ip}"
        self._index(asset)
        return asset, is_new

    @staticmethod
    def _merge_local_sources(asset: Asset, obs: Observation) -> None:
        """UPnP, HTTP, mDNS, NetBIOS y TTL: completan lo que SNMP no dio (SNMP tiene prioridad)."""
        random_vendor = not asset.vendor or asset.vendor.startswith("(")
        if obs.ttl:
            asset.attributes["ttl"] = obs.ttl
            asset.attributes["os_family"] = os_family_from_ttl(obs.ttl)
        if obs.netbios:
            asset.attributes["netbios"] = obs.netbios
        if obs.upnp:
            u = obs.upnp
            asset.attributes["upnp"] = u
            asset.serial = asset.serial or normalize_serial(u.get("serialNumber", ""))
            if is_generic_model(asset.model) and upnp_model(u):
                asset.model = upnp_model(u)
            if random_vendor and u.get("manufacturer"):
                asset.vendor = u["manufacturer"]
        if obs.mdns:
            m = obs.mdns
            asset.attributes["mdns"] = m
            if model := mdns.txt_value(m, *mdns.MODEL_TXT_KEYS):
                if is_generic_model(asset.model):
                    asset.model = model
            if random_vendor and (maker := mdns.txt_value(m, "usb_mfg", "manufacturer", "mfg")):
                asset.vendor = maker
            if name := mdns.txt_value(m, "name", "fn"):
                asset.attributes["announced_name"] = name
                # El nombre anunciado suele ser el modelo de fábrica («Pixel 9 Pro»); solo se usa si lo parece
                if brand := product_brand(name):
                    if is_generic_model(asset.model):
                        asset.model = name
                    if not asset.vendor or asset.vendor.startswith("("):
                        asset.vendor = brand
        if obs.http:
            asset.attributes["http"] = obs.http
            candidates = obs.http.get("model_candidates", [])
            # Un único candidato en la página de administración suele ser el modelo real (p.ej. HG8145X6)
            if len(candidates) == 1 and is_generic_model(asset.model):
                asset.model = candidates[0]
        if obs.is_probe:
            me = localhost.describe()
            asset.vendor = me["vendor"] or asset.vendor
            asset.model = me["model"] or asset.model
            asset.serial = normalize_serial(me["serial"]) or asset.serial
            asset.os = me["os"] or asset.os
            if me["chassis"]:
                asset.attributes["chassis"] = me["chassis"]
        if not asset.os and asset.attributes.get("os_family") == "windows":
            asset.os = "Windows (por TTL)"
