"""Controles de seguridad compartidos: límites de red, validación de URLs y defensa de la interfaz.

La sonda vive DENTRO de la red del cliente y procesa datos de equipos no confiables (SNMP, UPnP,
páginas web, mDNS) y configuración que llega de iurefficient. Aquí se concentran las barreras:

- qué IPs/redes son «internas» (para no dejar que un dato de la red lleve a la sonda a otra parte);
- qué rangos puede escanear una configuración remota (A2);
- validación de URLs devueltas por la IA, con resolución de DNS y sin seguir saltos a ciegas (A3/A4);
- allowlist de cabecera Host y token de la interfaz (C2, DNS rebinding, CSRF).
"""

from __future__ import annotations

import ipaddress
import secrets
import socket
from urllib.parse import urlsplit

# Redes que una configuración remota puede pedir escanear por omisión (A2): privadas + CGNAT.
# Un iurefficient comprometido no debe poder convertir las sondas en escáneres de internet.
DEFAULT_SCANNABLE = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),   # CGNAT
    ipaddress.ip_network("169.254.0.0/16"),  # link-local (algunas redes lo usan)
]

# Límites de la configuración recibida de iurefficient (A2).
MAX_CONCURRENCY = 1024
MIN_TCP_TIMEOUT = 0.2
MAX_TCP_TIMEOUT = 10.0
MIN_HEARTBEAT = 30
MAX_HEARTBEAT = 86400
MIN_SCHEDULE_INTERVAL = 30  # minutos; 0 = desactivado


def _ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def is_internal_ip(ip) -> bool:
    """IP que NO debe alcanzarse desde datos de la red (SSRF): privada, loopback, link-local, reservada…"""
    addr = _ip(ip) if isinstance(ip, str) else ip
    if addr is None:
        return True  # ante la duda, tratarla como interna (no alcanzable)
    return not addr.is_global


def is_literal_private_ip(host: str) -> bool:
    """True solo si `host` es un literal IP privado/loopback (no un nombre de dominio)."""
    addr = _ip(host)
    return addr is not None and not addr.is_global


# ---------------------------------------------------------------------------
# Rangos permitidos para escanear (configuración remota, A2)
# ---------------------------------------------------------------------------
def parse_networks(cidrs) -> list:
    nets = []
    for c in cidrs or []:
        try:
            nets.append(ipaddress.ip_network(str(c).strip(), strict=False))
        except ValueError:
            continue
    return nets


def allowed_scan_networks(settings: dict, local_cidrs: list[str]) -> list:
    """Redes que la sonda acepta escanear: las configuradas localmente, o por omisión las privadas
    más las redes propias de la sonda. La configuración remota NO puede ampliar esta lista."""
    configured = parse_networks(settings.get("allowed_networks"))
    if configured:
        return configured
    return DEFAULT_SCANNABLE + parse_networks(local_cidrs)


def targets_within(targets: list[str], allowed: list) -> bool:
    """True si TODAS las direcciones de los rangos caen dentro de alguna red permitida."""
    from . import netutil
    try:
        ips = netutil.expand_targets(targets)
    except ValueError:
        return False
    for ip in ips:
        addr = ipaddress.ip_address(ip)
        if not any(addr in net for net in allowed):
            return False
    return bool(ips)


def clamp_remote_config(config: dict, allowed: list) -> tuple[dict, list[str]]:
    """Recorta una configuración recibida de iurefficient a límites seguros (A2).

    Devuelve (configuración_saneada, avisos). Los rangos fuera de las redes permitidas se descartan.
    """
    safe: dict = {}
    warnings: list[str] = []
    if isinstance(config.get("targets"), list):
        if targets_within(config["targets"], allowed):
            safe["targets"] = config["targets"]
        else:
            warnings.append("rangos fuera de las redes permitidas: ignorados")
    for key, lo, hi, default in (("concurrency", 8, MAX_CONCURRENCY, None),
                                 ("heartbeat_seconds", MIN_HEARTBEAT, MAX_HEARTBEAT, None)):
        if key in config:
            try:
                safe[key] = max(lo, min(hi, int(config[key])))
            except (TypeError, ValueError):
                warnings.append(f"{key} inválido: ignorado")
    if "tcp_timeout" in config:
        try:
            safe["tcp_timeout"] = max(MIN_TCP_TIMEOUT, min(MAX_TCP_TIMEOUT, float(config["tcp_timeout"])))
        except (TypeError, ValueError):
            warnings.append("tcp_timeout inválido: ignorado")
    schedule = config.get("schedule") or {}
    if "interval_minutes" in schedule:
        try:
            iv = int(schedule["interval_minutes"] or 0)
            safe.setdefault("schedule", {})["interval_minutes"] = 0 if iv <= 0 else max(MIN_SCHEDULE_INTERVAL, iv)
        except (TypeError, ValueError):
            warnings.append("interval_minutes inválido: ignorado")
    if "window" in schedule:
        safe.setdefault("schedule", {})["window"] = schedule["window"]
    for key in ("collectors", "auto_sync", "auto_enrich"):
        if key in config:
            safe[key] = config[key]
    return safe, warnings


# ---------------------------------------------------------------------------
# URLs que la IA devuelve (A3/A4)
# ---------------------------------------------------------------------------
def is_safe_link(url: str) -> bool:
    """Para enlaces que se MUESTRAN en la interfaz: solo http(s) (nada de javascript:, data:, file:…)."""
    if not url or not isinstance(url, str):
        return False
    return urlsplit(url.strip()).scheme.lower() in ("http", "https")


def resolve_safe_target(url: str) -> tuple[str, str] | None:
    """Valida una URL para que la sonda la pueda PEDIR sin riesgo de SSRF.

    Resuelve el host y exige que TODAS sus IPs sean públicas. Devuelve (ip_pública, host) para
    conectarse a esa IP fija (y así evitar el rebinding entre validación y conexión), o None.
    """
    if not is_safe_link(url):
        return None
    parts = urlsplit(url.strip())
    host = parts.hostname
    if not host:
        return None
    port = parts.port or (443 if parts.scheme == "https" else 80)
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except OSError:
        return None
    ips = {info[4][0] for info in infos}
    if not ips or any(is_internal_ip(ip) for ip in ips):
        return None
    return next(iter(ips)), host


# ---------------------------------------------------------------------------
# Defensa de la interfaz web (C2)
# ---------------------------------------------------------------------------
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1", "[::1]"}


def is_loopback_bind(host: str) -> bool:
    return host in ("127.0.0.1", "localhost", "::1")


def allowed_hosts(bind_host: str, port: int) -> set[str]:
    """Valores aceptables de la cabecera Host (defensa contra DNS rebinding)."""
    names = set(LOOPBACK_HOSTS)
    if bind_host and bind_host not in ("0.0.0.0", "::"):
        names.add(bind_host)
    with_port = {f"{h}:{port}" for h in names}
    return names | with_port


def host_is_allowed(host_header: str, bind_host: str, port: int) -> bool:
    if not host_header:
        return False
    return host_header.strip().lower() in {h.lower() for h in allowed_hosts(bind_host, port)}


def new_ui_token() -> str:
    return secrets.token_urlsafe(24)
