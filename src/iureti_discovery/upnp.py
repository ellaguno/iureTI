"""SSDP / UPnP: módems, routers, TVs, impresoras y NAS publican fabricante, modelo y serie."""

from __future__ import annotations

import asyncio
import re
import socket
import time
import xml.etree.ElementTree as ET
from urllib.parse import urljoin, urlparse

import httpx

SSDP_ADDR = ("239.255.255.250", 1900)
MAX_DESCRIPTION_BYTES = 256 * 1024
FIELDS = ("deviceType", "friendlyName", "manufacturer", "manufacturerURL", "modelName", "modelNumber",
          "modelDescription", "modelURL", "serialNumber", "presentationURL")


def search(timeout: float = 3.0) -> dict[str, dict]:
    """M-SEARCH ssdp:all. Devuelve {ip: {"location", "server"}}. Bloqueante."""
    msg = (
        "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\n"
        "MX: 2\r\nST: ssdp:all\r\n\r\n"
    ).encode()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    sock.settimeout(0.5)
    found: dict[str, dict] = {}
    try:
        sock.sendto(msg, SSDP_ADDR)
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            try:
                data, (ip, _) = sock.recvfrom(8192)
            except socket.timeout:
                continue
            headers = {}
            for line in data.decode("utf-8", errors="replace").split("\r\n")[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()
            entry = found.setdefault(ip, {"location": "", "server": ""})
            location = headers.get("location", "")
            # Solo descripciones servidas por el mismo equipo que respondió
            if location and not entry["location"] and urlparse(location).hostname == ip:
                entry["location"] = location
            entry["server"] = entry["server"] or headers.get("server", "")
    except OSError:
        pass
    finally:
        sock.close()
    return found


def _strip_ns(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def parse_description(xml_text: str, base_url: str) -> dict:
    root = ET.fromstring(xml_text)
    device = next((el for el in root.iter() if _strip_ns(el.tag) == "device"), None)
    if device is None:
        return {}
    info: dict = {}
    for child in device:
        name = _strip_ns(child.tag)
        if name in FIELDS and (child.text or "").strip():
            info[name] = child.text.strip()
    icons = []
    for el in device.iter():
        if _strip_ns(el.tag) == "icon":
            icon = {_strip_ns(c.tag): (c.text or "").strip() for c in el}
            if icon.get("url"):
                icons.append({"url": urljoin(base_url, icon["url"]), "mimetype": icon.get("mimetype", ""),
                              "width": icon.get("width", "")})
    if icons:
        info["icons"] = icons[:4]
    if info.get("serialNumber"):
        if decoded := decode_gpon_serial(info["serialNumber"]):
            info["serialDecoded"] = decoded
    return info


def decode_gpon_serial(serial: str) -> str:
    """ONT GPON: 16 hex cuyo prefijo son 4 letras del fabricante (48575443… → HWTC…)."""
    if not re.fullmatch(r"[0-9A-Fa-f]{16}", serial):
        return ""
    try:
        vendor = bytes.fromhex(serial[:8]).decode("ascii")
    except (ValueError, UnicodeDecodeError):
        return ""
    return vendor + serial[8:].upper() if re.fullmatch(r"[A-Z]{4}", vendor) else ""


async def fetch_description(client: httpx.AsyncClient, ip: str, location: str) -> dict:
    if urlparse(location).hostname != ip:
        return {}
    try:
        async with client.stream("GET", location, timeout=3.0) as resp:
            if resp.status_code != 200:
                return {}
            body = b""
            async for chunk in resp.aiter_bytes():
                body += chunk
                if len(body) > MAX_DESCRIPTION_BYTES:
                    return {}
        return parse_description(body.decode("utf-8", errors="replace"), location)
    except (httpx.HTTPError, ET.ParseError, asyncio.TimeoutError):
        return {}
