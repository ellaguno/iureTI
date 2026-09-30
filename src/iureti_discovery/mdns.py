"""mDNS / DNS-SD (Bonjour): equipos que se anuncian en el segmento local.

Teléfonos Android (Nearby, KDE Connect), iPhone/Mac, impresoras, Chromecast/TV, HomeKit, NAS…
Solo alcanza el segmento L2 de la sonda (multicast 224.0.0.251).
"""

from __future__ import annotations

import time

from zeroconf import ServiceBrowser, Zeroconf, ZeroconfServiceTypes

MAX_TXT_VALUE = 120

# Tipos de servicio conocidos → (descripción, tipo de dispositivo sugerido o None)
SERVICE_HINTS: dict[str, tuple[str, str | None]] = {
    "_FC9F5ED42C8A._tcp": ("Google Nearby / Quick Share (Android)", "mobile"),
    "_kdeconnect._udp": ("KDE Connect", None),
    "_googlecast._tcp": ("Google Cast (Chromecast / TV / bocina)", "iot"),
    "_airplay._tcp": ("AirPlay", "iot"),
    "_raop._tcp": ("AirPlay audio", "iot"),
    "_companion-link._tcp": ("Apple (iPhone/iPad/Mac)", None),
    "_apple-mobdev2._tcp": ("Apple iOS", "mobile"),
    "_hap._tcp": ("HomeKit", "iot"),
    "_homekit._tcp": ("HomeKit", "iot"),
    "_matter._tcp": ("Matter", "iot"),
    "_ipp._tcp": ("Impresión IPP", "printer"),
    "_ipps._tcp": ("Impresión IPP", "printer"),
    "_printer._tcp": ("Impresión LPD", "printer"),
    "_pdl-datastream._tcp": ("Impresión RAW", "printer"),
    "_scanner._tcp": ("Escáner", "printer"),
    "_uscan._tcp": ("Escáner eSCL", "printer"),
    "_smb._tcp": ("Compartición SMB", None),
    "_afpovertcp._tcp": ("Compartición AFP", "nas"),
    "_nfs._tcp": ("NFS", "nas"),
    "_ssh._tcp": ("SSH", None),
    "_sftp-ssh._tcp": ("SFTP", None),
    "_workstation._tcp": ("Estación de trabajo", "workstation"),
    "_spotify-connect._tcp": ("Spotify Connect", "iot"),
    "_sonos._tcp": ("Sonos", "iot"),
    "_amzn-wplay._tcp": ("Amazon Fire TV", "iot"),
    "_androidtvremote2._tcp": ("Android TV", "iot"),
    "_meshcop._udp": ("Thread border router", "iot"),
}

_HINTS_LOWER = {k.lower(): v for k, v in SERVICE_HINTS.items()}

# Claves TXT que describen el producto (se pueden usar para identificarlo)
MODEL_TXT_KEYS = ("md", "model", "ty", "product", "usb_mdl", "usb_mfg", "manufacturer", "mfg", "mdl", "am")


def _decode(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    value = value.strip()
    return value if len(value) <= MAX_TXT_VALUE else value[:MAX_TXT_VALUE] + "…"


def normalize_type(service_type: str) -> str:
    return service_type.lower().removesuffix(".local.").rstrip(".")


def hint_for(service: str) -> tuple[str, str | None] | None:
    return _HINTS_LOWER.get(normalize_type(service))


def discover(stop=None, min_seconds: float = 6.0, max_seconds: float = 120.0) -> dict[str, dict]:
    """Escucha mDNS hasta que `stop` (threading.Event) se active y hayan pasado min_seconds.

    Los teléfonos en reposo contestan de forma intermitente: escuchar durante todo el escaneo, re-enumerar
    los tipos de servicio y consultar también los tipos conocidos da más oportunidades de verlos.
    Devuelve {ip: {"host", "services", "names", "txt"}}. Bloqueante: llamar con asyncio.to_thread.
    """
    zc = Zeroconf()
    found: dict[str, dict] = {}
    browsers: dict[str, ServiceBrowser] = {}

    class Listener:
        def add_service(self, zc_, type_, name):
            info = zc_.get_service_info(type_, name, timeout=1500)
            if not info:
                return
            stype = normalize_type(type_)
            host = (info.server or "").removesuffix(".local.").rstrip(".")
            txt = {_decode(k).lower(): _decode(v) for k, v in (info.properties or {}).items() if k}
            instance = name.removesuffix(type_).rstrip(".")
            for ip in info.parsed_addresses():
                if ":" in ip:  # solo IPv4 por ahora
                    continue
                entry = found.setdefault(ip, {"host": "", "services": [], "names": [], "txt": {}})
                entry["host"] = entry["host"] or host
                if stype not in entry["services"]:
                    entry["services"].append(stype)
                if instance and instance not in entry["names"]:
                    entry["names"].append(_decode(instance))
                for k, v in txt.items():
                    entry["txt"].setdefault(f"{stype}:{k}", v)

        update_service = add_service

        def remove_service(self, *args):
            pass

    def browse(types):
        for t in types:
            if t.lower() not in browsers:
                browsers[t.lower()] = ServiceBrowser(zc, t, Listener())

    start = time.monotonic()
    try:
        browse([t + ".local." for t in SERVICE_HINTS])
        while True:
            browse(ZeroconfServiceTypes.find(zc=zc, timeout=2.0))
            elapsed = time.monotonic() - start
            if elapsed >= max_seconds or (elapsed >= min_seconds and (stop is None or stop.is_set())):
                break
            time.sleep(1.0)
        for b in browsers.values():
            b.cancel()
    finally:
        zc.close()
    return found


def txt_value(mdns: dict, *keys: str) -> str:
    """Primer valor TXT (de cualquier servicio) cuya clave esté en keys."""
    for full_key, value in (mdns.get("txt") or {}).items():
        if full_key.split(":", 1)[-1] in keys and value:
            return value
    return ""
