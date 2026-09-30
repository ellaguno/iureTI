"""Enriquecimiento por internet: identifica el producto (nombre comercial, descripción, ficha y foto).

Usa Claude con búsqueda web. Solo se envían datos del PRODUCTO (marca, modelo, descripciones que el
equipo anuncia, puertos); nunca IPs, MACs, hostnames, números de serie, ubicaciones ni contactos.
Los resultados se guardan en caché por huella de producto: dos equipos del mismo modelo cuestan una consulta.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import socket
from pathlib import Path
from urllib.parse import urljoin, urlparse

import anthropic
import httpx

from . import mdns
from .models import DEVICE_TYPES, Asset, utcnow
from .oui import cache_dir
from .reconcile import is_generic_model, product_brand
from .sync import DEVICE_TYPE_LABELS, clean_vendor

DEFAULT_MODEL = "claude-opus-5-5"
MAX_IMAGE_BYTES = 5 * 1024 * 1024
MAX_PAGE_BYTES = 1024 * 1024

SYSTEM_PROMPT = """Eres analista de inventario de TI. Recibes la huella de red de UN equipo (lo que el propio \
equipo anuncia por SNMP, UPnP, mDNS o su página web de administración, más el fabricante de su MAC) y debes \
identificar el producto exacto.

Busca en la web para confirmar el modelo; no inventes. Las pistas pueden ser genéricas o contener ruido (por \
ejemplo, una página de administración con logotipos de varios proveedores de internet): contrasta los candidatos \
y quédate con el que sea consistente con el resto de la huella. Si no alcanza para saber el modelo exacto, \
identifica lo que sí se puede (fabricante, familia, tipo) y marca la confianza como "baja".

Al terminar, llama UNA vez a la herramienta report_device con el resultado. Textos en español.
- product_url: página oficial del producto si existe; si no, una ficha técnica confiable. Solo URLs que \
hayas visto en los resultados.
- image_url: URL directa (jpg/png/webp) de una foto del producto, de preferencia del fabricante o de una \
tienda reconocida, vista en los resultados. Cadena vacía si no encontraste una.
- specs: hasta 8 características clave (p. ej. "Wi-Fi 6 AX3000", "4 puertos GE", "GPON").
- support_status: vigente, descontinuado, fin de soporte (con año si se conoce) o cadena vacía."""

REPORT_TOOL = {
    "name": "report_device",
    "description": "Reporta la identificación final del equipo. Llamar una sola vez, al terminar.",
    "strict": True,
    "input_schema": {
        "type": "object",
        "properties": {
            "identified": {"type": "boolean"},
            "manufacturer": {"type": "string"},
            "product_name": {"type": "string"},
            "model": {"type": "string"},
            "device_type": {"type": "string", "enum": DEVICE_TYPES},
            "description": {"type": "string"},
            "specs": {"type": "array", "items": {"type": "string"}},
            "release_year": {"type": "string"},
            "support_status": {"type": "string"},
            "product_url": {"type": "string"},
            "image_url": {"type": "string"},
            "confidence": {"type": "string", "enum": ["alta", "media", "baja"]},
            "notes": {"type": "string"},
        },
        "required": ["identified", "manufacturer", "product_name", "model", "device_type", "description", "specs",
                     "release_year", "support_status", "product_url", "image_url", "confidence", "notes"],
        "additionalProperties": False,
    },
}


class EnrichError(RuntimeError):
    pass


# ---------------------------------------------------------------------------
# Qué se envía
# ---------------------------------------------------------------------------
def product_facts(asset: Asset) -> dict:
    """Solo datos del producto. Nada que identifique a la organización, la red o a una persona."""
    at = asset.attributes
    snmp, upnp, http, md = at.get("snmp") or {}, at.get("upnp") or {}, at.get("http") or {}, at.get("mdns") or {}
    facts = {
        "tipo_probable": DEVICE_TYPE_LABELS.get(asset.device_type, asset.device_type),
        "fabricante": clean_vendor(asset.vendor),
        "modelo": asset.model,
        "sistema": asset.os,
        "snmp_sysObjectID": snmp.get("sys_object_id", ""),
        "snmp_sysDescr": (snmp.get("sys_descr") or "")[:300],
        "upnp": {k: upnp[k] for k in ("deviceType", "manufacturer", "modelName", "modelNumber", "modelDescription",
                                      "server") if upnp.get(k)},
        "web": {k: http[k] for k in ("title", "server", "realm", "model_candidates") if http.get(k)},
        "mdns_servicios": md.get("services", []),
        "mdns_modelo": mdns.txt_value(md, *mdns.MODEL_TXT_KEYS),
        "nombre_anunciado": at.get("announced_name", "") if product_brand(at.get("announced_name", "")) else "",
        "familia_so_por_ttl": at.get("os_family", ""),
        "puertos_abiertos": asset.open_ports,
    }
    return _scrub({k: v for k, v in facts.items() if v}, _identifiers(asset))


def _identifiers(asset: Asset) -> list[str]:
    at = asset.attributes
    values = [asset.hostname, asset.hostname.split(".")[0], asset.serial, *asset.ips, *asset.macs,
              (at.get("snmp") or {}).get("sys_name", ""), (at.get("snmp") or {}).get("serial", ""),
              (at.get("netbios") or {}).get("name", ""), (at.get("mdns") or {}).get("host", ""),
              (at.get("upnp") or {}).get("serialNumber", ""), (at.get("upnp") or {}).get("serialDecoded", "")]
    return sorted({v for v in values if v and len(v) >= 3}, key=len, reverse=True)


def _scrub(value, identifiers: list[str]):
    """Última barrera: quita hostnames, series, IPs y MACs aunque vengan dentro de otro texto (p.ej. sysDescr)."""
    if isinstance(value, str):
        for ident in identifiers:
            value = re.sub(re.escape(ident), "[equipo]", value, flags=re.I)
        return value
    if isinstance(value, list):
        return [_scrub(v, identifiers) for v in value]
    if isinstance(value, dict):
        return {k: _scrub(v, identifiers) for k, v in value.items()}
    return value


def has_product_clues(facts: dict) -> bool:
    """Con solo el fabricante de la MAC no hay nada que buscar."""
    return any(facts.get(k) for k in ("modelo", "snmp_sysDescr", "upnp", "web", "mdns_modelo", "nombre_anunciado"))


def facts_key(facts: dict) -> str:
    stable = {k: v for k, v in facts.items() if k not in ("puertos_abiertos", "tipo_probable")}
    return hashlib.sha256(json.dumps(stable, sort_keys=True, ensure_ascii=False).encode()).hexdigest()[:32]


# ---------------------------------------------------------------------------
# Consulta a Claude
# ---------------------------------------------------------------------------
def make_client(api_key: str = "") -> anthropic.Anthropic:
    # Sin clave explícita, el SDK usa ANTHROPIC_API_KEY o el perfil de `ant auth login`
    return anthropic.Anthropic(api_key=api_key) if api_key else anthropic.Anthropic()


def identify(facts: dict, client: anthropic.Anthropic, model: str = DEFAULT_MODEL, max_rounds: int = 5) -> dict:
    messages = [{
        "role": "user",
        "content": "Huella del equipo (JSON):\n" + json.dumps(facts, ensure_ascii=False, indent=1),
    }]
    for _ in range(max_rounds):
        try:
            response = client.beta.messages.create(
                model=model,
                max_tokens=16000,
                betas=["server-side-fallback-2026-07-01"],
                fallbacks="default",
                output_config={"effort": "medium"},
                system=SYSTEM_PROMPT,
                tools=[{"type": "web_search_20260209", "name": "web_search", "max_uses": 5}, REPORT_TOOL],
                tool_choice={"type": "auto"},
                messages=messages,
            )
        except anthropic.AuthenticationError as exc:
            raise EnrichError("Clave de Anthropic inválida o ausente (Configuración › Búsqueda en internet)") from exc
        except anthropic.RateLimitError as exc:
            raise EnrichError("Límite de uso de la API de Anthropic alcanzado; intenta más tarde") from exc
        except anthropic.APIStatusError as exc:
            raise EnrichError(f"Error de la API de Anthropic ({exc.status_code}): {exc.message}") from exc
        except anthropic.APIConnectionError as exc:
            raise EnrichError("Sin conexión con la API de Anthropic") from exc

        if response.stop_reason == "refusal":
            raise EnrichError("La consulta fue rechazada por el modelo")
        report = next((b for b in response.content if b.type == "tool_use" and b.name == "report_device"), None)
        if report is not None:
            return dict(report.input)
        messages.append({"role": "assistant", "content": response.content})
        if response.stop_reason == "pause_turn":
            continue  # la búsqueda web sigue en curso: reenviar para continuar
        messages.append({"role": "user", "content": "Reporta el resultado con la herramienta report_device."})
    raise EnrichError("El modelo no reportó un resultado")


# ---------------------------------------------------------------------------
# Imagen del producto
# ---------------------------------------------------------------------------
def is_public_url(url: str) -> bool:
    """Evita que una URL devuelta por la búsqueda haga a la sonda consultar su propia red interna."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return False
    try:
        infos = socket.getaddrinfo(parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80))
    except OSError:
        return False
    return bool(infos) and all(ipaddress.ip_address(info[4][0]).is_global for info in infos)


_OG_IMAGE = re.compile(
    r'<meta[^>]+(?:property|name)=["\'](?:og:image|twitter:image)(?::src)?["\'][^>]*content=["\']([^"\']+)'
    r'|<meta[^>]+content=["\']([^"\']+)["\'][^>]*(?:property|name)=["\'](?:og:image|twitter:image)', re.I)


def page_image(client: httpx.Client, page_url: str) -> str:
    if not is_public_url(page_url):
        return ""
    try:
        with client.stream("GET", page_url) as resp:
            if resp.status_code != 200 or "html" not in resp.headers.get("content-type", ""):
                return ""
            body = b""
            for chunk in resp.iter_bytes():
                body += chunk
                if len(body) > MAX_PAGE_BYTES:
                    break
    except httpx.HTTPError:
        return ""
    m = _OG_IMAGE.search(body.decode("utf-8", errors="replace"))
    return urljoin(str(resp.url), m.group(1) or m.group(2)) if m else ""


EXTENSIONS = {"image/jpeg": ".jpg", "image/png": ".png", "image/webp": ".webp", "image/gif": ".gif"}


def images_dir() -> Path:
    path = cache_dir() / "images"
    path.mkdir(parents=True, exist_ok=True)
    return path


def download_image(client: httpx.Client, url: str) -> str:
    """Descarga y valida la imagen; devuelve el nombre del archivo en caché o ''."""
    if not url or not is_public_url(url):
        return ""
    name = hashlib.sha1(url.encode()).hexdigest()[:20]
    try:
        with client.stream("GET", url) as resp:
            ctype = resp.headers.get("content-type", "").split(";")[0].strip().lower()
            if resp.status_code != 200 or ctype not in EXTENSIONS:
                return ""
            data = b""
            for chunk in resp.iter_bytes():
                data += chunk
                if len(data) > MAX_IMAGE_BYTES:
                    return ""
    except httpx.HTTPError:
        return ""
    if len(data) < 1024:  # píxeles de seguimiento, íconos rotos
        return ""
    filename = name + EXTENSIONS[ctype]
    (images_dir() / filename).write_bytes(data)
    return filename


def resolve_image(result: dict) -> tuple[str, str]:
    """(url, archivo) de la primera imagen válida: la que dio la búsqueda o la og:image de la página del producto."""
    headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) iureti-discovery"}
    with httpx.Client(timeout=10.0, follow_redirects=True, headers=headers) as client:
        candidates = [result.get("image_url", "")]
        if result.get("product_url"):
            candidates.append(page_image(client, result["product_url"]))
        for url in filter(None, candidates):
            if filename := download_image(client, url):
                return url, filename
    return "", ""


# ---------------------------------------------------------------------------
# Aplicar al activo
# ---------------------------------------------------------------------------
def apply(asset: Asset, enrichment: dict) -> None:
    asset.attributes["enrichment"] = enrichment
    if not enrichment.get("identified") or enrichment.get("confidence") == "baja":
        return
    if is_generic_model(asset.model) and (enrichment.get("model") or enrichment.get("product_name")):
        asset.model = enrichment.get("model") or enrichment["product_name"]
    if (not asset.vendor or asset.vendor.startswith("(")) and enrichment.get("manufacturer"):
        asset.vendor = enrichment["manufacturer"]
