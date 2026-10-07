"""Conciliación de observaciones con activos existentes (deduplicación)."""

from __future__ import annotations

import re
from dataclasses import asdict

from . import localhost, mdns, virtual
from .classify import ENTERPRISES, classify, enterprise_number
from .models import Asset, Observation
from .netutil import is_locally_administered, normalize_mac, os_family_from_ttl

# MACs que no identifican a nadie: interfaces sin dirección (GLPI-Agent reporta 00:00:00:00:00:00)
# y broadcast. Misma regla que iurefficient (plugins/iur_inventory/identity.py).
JUNK_MACS = {"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"}

# MACs localmente administradas que NO son aleatorias sino derivadas de otra cosa, y por eso
# se repiten entre equipos distintos: Docker forma 02:42:<ip del contenedor>, así que dos
# contenedores con la misma IP de puente en hosts distintos comparten MAC. Esas no sirven ni
# como clave débil. Misma lista que iurefficient (identity.py).
DETERMINISTIC_LOCAL_MAC_PREFIXES = ("02:42:",)

# Nombre sintético que macOS anuncia por NetBIOS cuando el nombre real no cabe en SMB
# («MacBook-Air-de-Sofía» → «MAC-4C0ED6», con el final de la MAC de fábrica). Cambia de una
# corrida a otra según conteste NetBIOS o no, así que no identifica: visto duplicar una Mac.
_SYNTHETIC_HOSTNAME = re.compile(r"mac-[0-9a-f]{6}")

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
    h = h.split(".")[0]
    if _SYNTHETIC_HOSTNAME.fullmatch(h):
        return ""
    return h


def is_weak_identity_mac(mac: str) -> bool:
    """MAC localmente administrada (privada/aleatoria) que sí puede servir como clave DÉBIL.

    No identifica en el sentido fuerte (el mismo equipo la cambia al cambiar de red o al rotar),
    pero una coincidencia exacta de 46 bits aleatorios es el mismo aparato: usarla para CASAR solo
    puede juntar lo que ya era uno; lo que no puede es garantizar que lo encuentre. Va después de
    serie, MAC universal y hostname, y fuera quedan las derivadas (Docker).
    """
    mac = normalize_mac(mac)
    return (bool(mac) and mac not in JUNK_MACS and is_locally_administered(mac)
            and not mac.startswith(DETERMINISTIC_LOCAL_MAC_PREFIXES))


def identity_keys(serial: str = "", macs: list[str] = (), hostname: str = "") -> list[str]:
    """Claves en orden de prioridad: serie > MAC universal > hostname > MAC local (débil)."""
    keys = []
    if s := normalize_serial(serial):
        keys.append(f"serial:{s}")
    for mac in macs:
        mac = normalize_mac(mac)
        if mac and mac not in JUNK_MACS and not is_locally_administered(mac):
            keys.append(f"mac:{mac}")
    if h := normalize_hostname(hostname):
        keys.append(f"host:{h}")
    for mac in macs:
        if is_weak_identity_mac(mac):
            keys.append(f"localmac:{normalize_mac(mac)}")
    return keys


def guest_scope(virtual: dict | None) -> str:
    """Ámbito de la IP de un invitado que solo se ve desde su anfitrión (contenedor en red NAT).

    172.17.0.2 existe en cada servidor con Docker: la IP solo tiene sentido junto con el anfitrión.
    '' para los equipos que se alcanzan desde la red (su IP es única en ella).
    """
    v = virtual or {}
    if v.get("reach") != "host":
        return ""
    return v.get("host_name") or v.get("host_ip") or ""


def guest_key(virtual: dict | None, macs: list[str], ip: str) -> str:
    """Clave de identidad propia de la sonda para un invitado sin identidad propia (contenedor NAT).

    No forma parte del contrato de paridad con iurefficient: allá solo llega como `fingerprint`.
    """
    scope = guest_scope(virtual)
    if not scope:
        return ""
    mac = next((normalize_mac(m) for m in macs if normalize_mac(m) and normalize_mac(m) not in JUNK_MACS), "")
    return f"guest:{scope}/{mac or ip}"


def asset_keys(asset: Asset) -> list[str]:
    keys = identity_keys(asset.serial, asset.macs, asset.hostname)
    # Otros nombres con los que se vio el mismo equipo (NetBIOS, mDNS, sysName…): un escaneo que solo
    # trae uno de ellos debe reconocerlo igual. Van después de las claves principales.
    for name in asset.attributes.get("names") or []:
        if (h := normalize_hostname(name)) and f"host:{h}" not in keys:
            keys.append(f"host:{h}")
    if key := guest_key(asset.attributes.get("virtual"), asset.macs, asset.ips[0] if asset.ips else ""):
        keys.append(key)
    return keys


def observed_hostname(obs: Observation) -> str:
    """DNS inverso > sysName SNMP > NetBIOS > nombre mDNS > nombre de la VM en el anfitrión."""
    return next(iter(observed_names(obs)), "")


def observed_names(obs: Observation) -> list[str]:
    """Todos los nombres que identifican al equipo en esta observación, por prioridad."""
    names = []
    for name in (obs.hostname, obs.snmp.sys_name if obs.snmp else "",
                 (obs.netbios or {}).get("name", ""), (obs.mdns or {}).get("host", ""),
                 (obs.virtual or {}).get("name", "")):
        if normalize_hostname(name) and name not in names:
            names.append(name)
    return names


def observed_serial(obs: Observation) -> str:
    return normalize_serial(obs.snmp.serial if obs.snmp else "") or normalize_serial((obs.upnp or {}).get("serialNumber", ""))


def observation_keys(obs: Observation) -> list[str]:
    names = observed_names(obs)
    keys = identity_keys(observed_serial(obs), [obs.mac] if obs.mac else [], names[0] if names else "")
    for name in names[1:]:
        if (key := f"host:{normalize_hostname(name)}") not in keys:
            keys.append(key)
    if key := guest_key(obs.virtual, [obs.mac] if obs.mac else [], obs.ip):
        keys.append(key)
    return keys


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
        self.assets: dict[str, Asset] = {}
        self.index: dict[str, str] = {}
        self.ip_index: dict[tuple[str, str], str] = {}  # (ámbito, ip) → id
        self.removed: dict[str, str] = {}  # id de activo absorbido → id del que lo absorbió
        # Duplicados que ya estaban en la base (reglas de identidad anteriores, nombres distintos en
        # escaneos distintos…) se consolidan al cargar: el más antiguo se queda con todo.
        for a in sorted(assets, key=lambda a: a.first_seen):
            others = [self.assets[i] for i in dict.fromkeys(self.index[k] for k in asset_keys(a) if k in self.index)]
            if others:
                self._absorb(others[0], a)
                self.removed[a.id] = others[0].id
                for extra in others[1:]:
                    self._absorb(others[0], extra)
                    self._drop(extra, others[0].id)
                self._index(others[0])
            else:
                self.assets[a.id] = a
                self._index(a)

    def _index(self, asset: Asset) -> None:
        for key in asset_keys(asset):
            self.index.setdefault(key, asset.id)
        scope = guest_scope(asset.attributes.get("virtual"))
        for ip in asset.ips:
            self.ip_index[(scope, ip)] = asset.id

    def _drop(self, asset: Asset, into: str) -> None:
        """Saca de los índices (y de la lista) un activo absorbido por otro."""
        self.assets.pop(asset.id, None)
        self.removed[asset.id] = into
        for key, owner in list(self.index.items()):
            if owner == asset.id:
                self.index[key] = into
        for key, owner in list(self.ip_index.items()):
            if owner == asset.id:
                self.ip_index[key] = into

    @staticmethod
    def _absorb(primary: Asset, other: Asset) -> None:
        """Todo lo del duplicado pasa al activo principal; el duplicado desaparece."""
        for field_name in ("ips", "macs"):
            merged = getattr(primary, field_name) + [x for x in getattr(other, field_name) if x not in getattr(primary, field_name)]
            setattr(primary, field_name, merged)
        primary.sources = sorted(set(primary.sources) | set(other.sources))
        primary.first_seen = min(primary.first_seen, other.first_seen) if other.first_seen else primary.first_seen
        if other.last_seen > primary.last_seen:  # el duplicado traía datos más recientes
            for field_name in ("hostname", "vendor", "model", "serial", "os", "location", "open_ports"):
                if getattr(other, field_name):
                    setattr(primary, field_name, getattr(other, field_name))
            primary.last_seen = other.last_seen
        else:
            for field_name in ("hostname", "vendor", "model", "serial", "os", "location"):
                if not getattr(primary, field_name) and getattr(other, field_name):
                    setattr(primary, field_name, getattr(other, field_name))
        for key, value in other.attributes.items():
            primary.attributes.setdefault(key, value)
        names = list(dict.fromkeys((primary.attributes.get("names") or []) + (other.attributes.get("names") or [])
                                   + [n for n in (primary.hostname, other.hostname) if n]))
        primary.attributes["names"] = names[:12]
        if other.type_locked and not primary.type_locked:
            primary.device_type, primary.type_locked = other.device_type, True
        if not primary.inventory_id and other.inventory_id:
            primary.inventory_id, primary.remote_status = other.inventory_id, other.remote_status
        if other.notes and other.notes not in primary.notes:
            primary.notes = (primary.notes + "\n" + other.notes).strip()
        merged_from = primary.attributes.get("merged_from") or []
        for entry in [{"id": other.id, "fingerprint": other.fingerprint}] + (other.attributes.get("merged_from") or []):
            if entry not in merged_from:
                merged_from.append(entry)
        primary.attributes["merged_from"] = merged_from[:20]
        primary.synced_at = ""  # hay que volver a enviarlo: iurefficient debe saber que absorbió a otro

    def _candidates(self, obs: Observation, keys: list[str]) -> list[Asset]:
        """Activos que esta observación reconoce, por prioridad de clave. Más de uno = duplicados."""
        ids = list(dict.fromkeys(self.index[k] for k in keys if k in self.index))
        owner = self.ip_index.get((guest_scope(obs.virtual), obs.ip))
        if owner and owner not in ids:
            candidate = self.assets[owner]
            # Observación sin identidad (p.ej. esta vez no hubo ARP): se asume el mismo equipo de esa IP.
            # Observación con identidad nueva: solo "mejora" a un activo que se conocía únicamente por IP.
            if not keys or not asset_keys(candidate):
                ids.append(owner)
        return [self.assets[i] for i in ids]

    def merge(self, obs: Observation) -> tuple[Asset, bool]:
        """Incorpora la observación. Devuelve (activo, es_nuevo).

        Si la observación casa con varios activos (la MAC con uno, el nombre con otro), eran el mismo
        equipo visto en escaneos distintos: se fusionan en el de la clave más fuerte.
        """
        keys = observation_keys(obs)
        found = self._candidates(obs, keys)
        is_new = not found
        if is_new:
            asset = Asset(first_seen=obs.observed_at)
            self.assets[asset.id] = asset
        else:
            asset = found[0]
            for other in found[1:]:
                self._absorb(asset, other)
                self._drop(other, asset.id)

        # La IP ya no pertenece a otro activo (p.ej. DHCP la reasignó)
        scope = guest_scope(obs.virtual)
        prev_owner = self.ip_index.get((scope, obs.ip))
        if prev_owner and prev_owner != asset.id:
            other = self.assets[prev_owner]
            other.ips = [ip for ip in other.ips if ip != obs.ip]

        asset.ips = _prepend_unique(asset.ips, obs.ip)
        asset.macs = _prepend_unique(asset.macs, normalize_mac(obs.mac))
        snmp = obs.snmp
        if hostname := observed_hostname(obs):
            asset.hostname = hostname
        if names := observed_names(obs):
            asset.attributes["names"] = list(dict.fromkeys(names + (asset.attributes.get("names") or [])))[:12]
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
        if obs.virtual_net:
            asset.attributes["virtual_net"] = obs.virtual_net
            if not obs.virtual:
                obs.virtual = virtual.probe_guest(obs.virtual_net)
        else:
            asset.attributes.pop("virtual_net", None)
        if obs.mac_from:
            asset.attributes["mac_from"] = obs.mac_from
        elif obs.mac:
            asset.attributes.pop("mac_from", None)
        self._merge_virtual(asset, obs)

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
    def _merge_virtual(asset: Asset, obs: Observation) -> None:
        """Lo virtual no deja de serlo: una observación sin evidencia conserva lo que ya se sabía;
        una con evidencia nueva la reemplaza, sin perder el anfitrión si esta vez no se vio."""
        if obs.virtual:
            previous = asset.attributes.get("virtual") or {}
            current = dict(obs.virtual)
            if not current.get("host_ip") and not current.get("host_name"):
                for key in ("host_ip", "host_name", "host_id", "confidence", "evidence"):
                    if previous.get(key):
                        current.setdefault(key, previous[key])
            asset.attributes["virtual"] = current
        if obs.hosting is not None:
            asset.attributes["hosting"] = obs.hosting
        elif obs.snmp is not None:
            asset.attributes.pop("hosting", None)  # respondió SNMP y ya no aloja nada

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
