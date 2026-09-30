"""Conciliación de observaciones con activos existentes (deduplicación)."""

from __future__ import annotations

import re
from dataclasses import asdict

from .classify import ENTERPRISES, classify, enterprise_number
from .models import Asset, Observation
from .netutil import is_locally_administered, normalize_mac

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
        if mac and not is_locally_administered(mac):
            keys.append(f"mac:{mac}")
    if h := normalize_hostname(hostname):
        keys.append(f"host:{h}")
    return keys


def asset_keys(asset: Asset) -> list[str]:
    return identity_keys(asset.serial, asset.macs, asset.hostname)


def observation_keys(obs: Observation) -> list[str]:
    snmp = obs.snmp
    hostname = obs.hostname or (snmp.sys_name if snmp else "")
    return identity_keys(snmp.serial if snmp else "", [obs.mac] if obs.mac else [], hostname)


def _prepend_unique(items: list, value) -> list:
    if not value:
        return items
    return [value] + [i for i in items if i != value]


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
        hostname = obs.hostname or (snmp.sys_name if snmp else "")
        if hostname:
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

        if not asset.type_locked:
            asset.device_type, asset.confidence, asset.reasons = classify(asset)

        keys = asset_keys(asset)
        asset.fingerprint = keys[0] if keys else f"ip:{obs.ip}"
        self._index(asset)
        return asset, is_new
