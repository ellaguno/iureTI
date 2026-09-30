"""Huella HTTP: encabezado Server, título, realm de autenticación y posibles modelos en la página."""

from __future__ import annotations

import html
import re
from collections import Counter

import httpx

MAX_BODY = 256 * 1024
WEB_PORTS = [(80, "http"), (8080, "http"), (443, "https"), (8443, "https")]

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_REALM_RE = re.compile(r'realm="([^"]{1,80})"', re.I)
# Tokens con letras y dígitos que parecen número de modelo: HG8145X6, TL-WR840N, RT-AX58U, MFC-L2710DW
_MODEL_RE = re.compile(r"\b(?=[A-Z0-9-]*\d)(?=[A-Z0-9-]*[A-Z])[A-Z]{1,6}-?[A-Z]{0,4}\d{2,5}[A-Z0-9-]{0,8}\b")
_NOT_MODELS = re.compile(r"^(UTF-?8|ISO-?8859.*|HTTP\d*|HTML\d*|CSS\d*|X-UA.*|IE\d+|ES\d+|H\d|MD5|SHA\d*|AES\d*|"
                         r"RC\d|UTF16|WIN\d+|X\d+|V\d+|\d+X\d+|Y20\d\d|[A-Z]\d)$")


_HEX_COLOR = re.compile(r"^[0-9A-F]{6}([0-9A-F]{2})?$")


def model_candidates(text: str, limit: int = 5) -> list[str]:
    counts = Counter(m for m in _MODEL_RE.findall(text)
                     if not _NOT_MODELS.match(m) and not _HEX_COLOR.match(m) and len(m) >= 4)
    return [m for m, _ in counts.most_common(limit)]


def parse(headers: dict, body: str) -> dict:
    info = {}
    if server := headers.get("server", "").strip():
        info["server"] = server[:120]
    if m := _REALM_RE.search(headers.get("www-authenticate", "")):
        info["realm"] = m.group(1)
    if m := _TITLE_RE.search(body):
        title = " ".join(html.unescape(m.group(1)).split())
        if title:
            info["title"] = title[:120]
    candidates = model_candidates(" ".join([info.get("title", ""), info.get("realm", ""), body]))
    if candidates:
        info["model_candidates"] = candidates
    return info


async def probe(client: httpx.AsyncClient, ip: str, open_ports: list[int]) -> dict:
    """Consulta la página raíz del primer puerto web abierto (sin seguir redirecciones a otros hosts)."""
    for port, scheme in WEB_PORTS:
        if port not in open_ports:
            continue
        url = f"{scheme}://{ip}:{port}/"
        try:
            for _ in range(3):
                async with client.stream("GET", url, timeout=4.0) as resp:
                    body = b""
                    async for chunk in resp.aiter_bytes():
                        body += chunk
                        if len(body) > MAX_BODY:
                            break
                    location = resp.headers.get("location", "")
                    next_url = resp.url.join(location) if resp.is_redirect and location else None
                    if next_url is not None and next_url.host == ip:
                        url = str(next_url)
                        continue
                    info = parse({k.lower(): v for k, v in resp.headers.items()}, body.decode("utf-8", errors="replace"))
                    info["url"] = url
                    info["status"] = resp.status_code
                    return info
        except (httpx.HTTPError, UnicodeError):
            continue
    return {}
