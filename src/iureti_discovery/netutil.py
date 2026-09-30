"""Utilidades de red que funcionan sin privilegios de root."""

from __future__ import annotations

import asyncio
import errno
import ipaddress
import json
import re
import shutil
import socket
import subprocess
from dataclasses import dataclass

MAX_TARGETS = 65536
VIRTUAL_IFACE_PREFIXES = ("docker", "br-", "veth", "lxcbr", "virbr", "vmnet", "tun", "tap", "wg", "cni", "flannel")


@dataclass
class LocalNetwork:
    interface: str
    address: str
    network: str
    virtual: bool


def local_networks() -> list[LocalNetwork]:
    """Redes IPv4 configuradas en las interfaces locales (excepto loopback)."""
    try:
        out = subprocess.run(["ip", "-j", "-4", "addr", "show"], capture_output=True, text=True, check=True).stdout
        data = json.loads(out)
    except (OSError, subprocess.CalledProcessError, json.JSONDecodeError):
        return []
    nets = []
    for iface in data:
        name = iface.get("ifname", "")
        if name == "lo":
            continue
        for addr in iface.get("addr_info", []):
            if addr.get("family") != "inet":
                continue
            iface_net = ipaddress.ip_interface(f"{addr['local']}/{addr['prefixlen']}")
            nets.append(
                LocalNetwork(
                    interface=name,
                    address=str(iface_net.ip),
                    network=str(iface_net.network),
                    virtual=name.startswith(VIRTUAL_IFACE_PREFIXES),
                )
            )
    return nets


_RANGE_RE = re.compile(r"^(\d+\.\d+\.\d+\.\d+)\s*-\s*(\d+\.\d+\.\d+\.\d+|\d+)$")


def expand_targets(targets: list[str], limit: int = MAX_TARGETS) -> list[str]:
    """Convierte CIDRs, rangos (a.b.c.d-e / a.b.c.d-w.x.y.z) e IPs sueltas en una lista de IPs."""
    seen: dict[str, None] = {}
    for raw in targets:
        for part in re.split(r"[,\s]+", raw.strip()):
            if not part:
                continue
            m = _RANGE_RE.match(part)
            if m:
                start = ipaddress.IPv4Address(m.group(1))
                end_s = m.group(2)
                end = ipaddress.IPv4Address(end_s) if "." in end_s else ipaddress.IPv4Address(
                    int(start) - (int(start) & 0xFF) + int(end_s)
                )
                if int(end) < int(start):
                    raise ValueError(f"Rango inválido: {part}")
                if int(end) - int(start) + 1 > limit:
                    raise ValueError(f"Demasiadas direcciones en {part} (límite {limit})")
                for i in range(int(start), int(end) + 1):
                    seen[str(ipaddress.IPv4Address(i))] = None
            elif "/" in part:
                net = ipaddress.IPv4Network(part, strict=False)
                if net.num_addresses > limit:
                    raise ValueError(f"Red demasiado grande: {part} (límite {limit} direcciones)")
                hosts = list(net.hosts()) if net.prefixlen < 31 else list(net)
                for ip in hosts:
                    seen[str(ip)] = None
            else:
                seen[str(ipaddress.IPv4Address(part))] = None
            if len(seen) > limit:
                raise ValueError(f"Demasiados objetivos (límite {limit})")
    return list(seen)


# Resultado de un sondeo TCP
OPEN, CLOSED, FILTERED = "open", "closed", "filtered"


async def tcp_probe(ip: str, port: int, timeout: float) -> str:
    """OPEN si conecta, CLOSED si el host responde con RST (está vivo), FILTERED si no hay respuesta."""
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
    except asyncio.TimeoutError:
        return FILTERED
    except ConnectionRefusedError:
        return CLOSED
    except OSError as exc:
        if exc.errno == errno.ECONNREFUSED:
            return CLOSED
        return FILTERED
    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), 0.5)
    except (asyncio.TimeoutError, OSError):
        pass
    return OPEN


_PING = shutil.which("ping")


async def ping(ip: str, timeout: float = 1.0) -> bool:
    if not _PING:
        return False
    try:
        proc = await asyncio.create_subprocess_exec(
            _PING, "-c", "1", "-n", "-q", "-W", str(max(1, round(timeout))), ip,
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
        )
        return await asyncio.wait_for(proc.wait(), timeout + 2) == 0
    except (OSError, asyncio.TimeoutError):
        return False


def default_gateways() -> set[str]:
    """IPs de las puertas de enlace por omisión de este equipo."""
    try:
        out = subprocess.run(["ip", "-j", "-4", "route", "show", "default"], capture_output=True, text=True, check=True).stdout
        return {r["gateway"] for r in json.loads(out) if r.get("gateway")}
    except (OSError, subprocess.CalledProcessError, json.JSONDecodeError):
        return set()


def read_arp_cache() -> dict[str, str]:
    """IP → MAC desde la caché ARP del kernel (solo entradas completas)."""
    result = {}
    try:
        with open("/proc/net/arp") as fh:
            next(fh)
            for line in fh:
                cols = line.split()
                if len(cols) >= 4 and cols[2] != "0x0" and cols[3] != "00:00:00:00:00:00":
                    result[cols[0]] = cols[3].lower()
    except OSError:
        pass
    return result


async def reverse_dns(ip: str, timeout: float = 2.0) -> str:
    loop = asyncio.get_running_loop()
    try:
        host, _, _ = await asyncio.wait_for(loop.run_in_executor(None, socket.gethostbyaddr, ip), timeout)
        # systemd-resolved sintetiza «_gateway» / «_outbound»: no son nombres reales del equipo
        return "" if host.startswith("_") else host
    except (OSError, asyncio.TimeoutError):
        return ""


def normalize_mac(mac: str) -> str:
    hexdigits = re.sub(r"[^0-9a-fA-F]", "", mac or "")
    if len(hexdigits) != 12:
        return ""
    return ":".join(hexdigits[i : i + 2] for i in range(0, 12, 2)).lower()


def is_locally_administered(mac: str) -> bool:
    """MAC aleatoria / local (bit 1 del primer octeto). No sirve como identidad ni para fabricante."""
    mac = normalize_mac(mac)
    return bool(mac) and bool(int(mac[:2], 16) & 0x02)
