"""Enriquecimiento por internet: identifica el producto (nombre comercial, descripción, ficha y foto).

Proveedores: OpenRouter (cualquier modelo: Gemini, GPT, DeepSeek, Qwen…, con el plugin de búsqueda web)
o Anthropic directo (Claude con búsqueda web). Solo se envían datos del PRODUCTO (marca, modelo, descripciones que el
equipo anuncia, puertos); nunca IPs, MACs, hostnames, números de serie, ubicaciones ni contactos.
Los resultados se guardan en caché por huella de producto: dos equipos del mismo modelo cuestan una consulta.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import anthropic
import httpx

from . import mdns, security
from .models import DEVICE_TYPES, Asset, utcnow
from .oui import cache_dir
from .reconcile import is_generic_model, product_brand
from .sync import DEVICE_TYPE_LABELS, clean_vendor

DEFAULT_MODEL = "claude-opus-5-5"  # proveedor Anthropic
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
OPENROUTER_DEFAULT_MODEL = "google/gemini-3.1-flash-lite"
# Sugerencias para la interfaz (precio USD por millón de tokens de entrada/salida, catálogo 2026-09-30).
# Se puede escribir cualquier otro modelo de openrouter.ai/models que soporte structured_outputs.
OPENROUTER_MODELS = [
    ("google/gemini-3.1-flash-lite", "Gemini 3.1 Flash Lite — recomendado ($0.25 / $1.50)"),
    ("google/gemini-2.5-flash-lite", "Gemini 2.5 Flash Lite — muy barato ($0.10 / $0.40)"),
    ("openai/gpt-6-luna", "GPT-6 Luna — muy barato ($0.10 / $0.50)"),
    ("deepseek/deepseek-v4-flash", "DeepSeek V4 Flash — el más barato ($0.08 / $0.16)"),
    ("qwen/qwen3.8-flash", "Qwen 3.8 Flash ($0.15 / $0.47)"),
    ("openai/gpt-5-mini", "GPT-5 mini ($0.25 / $2.00)"),
    ("google/gemini-3.5-flash", "Gemini 3.5 Flash — más preciso ($1.50 / $9.00)"),
    ("~anthropic/claude-haiku-latest", "Claude Haiku vía OpenRouter ($1 / $5)"),
]
WEB_ENGINES = ("exa", "native", "auto")  # exa: $0.007 por búsqueda, funciona con cualquier modelo
MAX_IMAGE_BYTES = 5 * 1024 * 1024
MAX_PAGE_BYTES = 1024 * 1024

SYSTEM_PROMPT = """Eres analista de inventario de TI. Recibes la huella de red de UN equipo (lo que el propio \
equipo anuncia por SNMP, UPnP, mDNS o su página web de administración, más el fabricante de su MAC) y debes \
identificar el producto exacto.

Busca en la web para confirmar el modelo; no inventes. Las pistas pueden ser genéricas o contener ruido (por \
ejemplo, una página de administración con logotipos de varios proveedores de internet): contrasta los candidatos \
y quédate con el que sea consistente con el resto de la huella. Si no alcanza para saber el modelo exacto, \
identifica lo que sí se puede (fabricante, familia, tipo) y marca la confianza como "baja".

Textos en español.
- product_url: página oficial del producto si existe; si no, una ficha técnica confiable. Solo URLs que \
hayas visto en los resultados.
- image_url: URL directa (jpg/png/webp) de una foto del producto, de preferencia del fabricante o de una \
tienda reconocida, vista en los resultados. Cadena vacía si no encontraste una.
- specs: hasta 8 características clave (p. ej. "Wi-Fi 6 AX3000", "4 puertos GE", "GPON").
- support_status: vigente, descontinuado, fin de soporte (con año si se conoce) o cadena vacía."""

ANTHROPIC_ENDING = "\n\nAl terminar, llama UNA vez a la herramienta report_device con el resultado."
JSON_ENDING = ("\n\nResponde ÚNICAMENTE con un objeto JSON con estas claves: identified (boolean), manufacturer, "
               "product_name, model, device_type (uno de: " + ", ".join(DEVICE_TYPES) + "), description, specs "
               "(lista de textos), release_year, support_status, product_url, image_url, confidence (alta, media o "
               "baja), notes. Sin texto adicional.")

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
def _user_message(facts: dict) -> str:
    return "Huella del equipo (JSON):\n" + json.dumps(facts, ensure_ascii=False, indent=1)


def normalize_report(data: dict) -> dict:
    """Valida y normaliza la respuesta (los modelos baratos no siempre respetan el esquema)."""
    if not isinstance(data, dict):
        raise EnrichError("La respuesta del modelo no es un objeto JSON")
    text = lambda k: str(data.get(k) or "").strip()  # noqa: E731
    specs = data.get("specs") or []
    report = {
        "identified": bool(data.get("identified")),
        "manufacturer": text("manufacturer"),
        "product_name": text("product_name"),
        "model": text("model"),
        "device_type": text("device_type") if text("device_type") in DEVICE_TYPES else "unknown",
        "description": text("description"),
        "specs": [str(x).strip() for x in specs if str(x).strip()][:8] if isinstance(specs, list) else [],
        "release_year": text("release_year"),
        "support_status": text("support_status"),
        # Solo http(s): el modelo podría devolver javascript:/data: y la ficha es clicable (A3).
        "product_url": text("product_url") if security.is_safe_link(text("product_url")) else "",
        "image_url": text("image_url") if security.is_safe_link(text("image_url")) else "",
        "confidence": text("confidence").lower() if text("confidence").lower() in ("alta", "media", "baja") else "baja",
        "notes": text("notes"),
    }
    if report["identified"] and not (report["product_name"] or report["model"]):
        report["identified"] = False
    return report


def parse_json_text(content: str) -> dict:
    """Acepta JSON puro o envuelto en ```json … ``` / texto alrededor."""
    content = (content or "").strip()
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        start, end = content.find("{"), content.rfind("}")
        if start == -1 or end <= start:
            raise EnrichError("El modelo no devolvió JSON") from None
        try:
            return json.loads(content[start : end + 1])
        except json.JSONDecodeError as exc:
            raise EnrichError("El modelo devolvió JSON inválido") from exc


# --- Anthropic ---------------------------------------------------------------
def make_client(api_key: str = "") -> anthropic.Anthropic:
    # Sin clave explícita, el SDK usa ANTHROPIC_API_KEY o el perfil de `ant auth login`
    return anthropic.Anthropic(api_key=api_key) if api_key else anthropic.Anthropic()


def identify(facts: dict, client: anthropic.Anthropic, model: str = DEFAULT_MODEL, max_rounds: int = 5) -> dict:
    """Claude con búsqueda web; el resultado llega por la herramienta estricta report_device."""
    messages = [{"role": "user", "content": _user_message(facts)}]
    for _ in range(max_rounds):
        try:
            response = client.beta.messages.create(
                model=model,
                max_tokens=16000,
                betas=["server-side-fallback-2026-07-01"],
                fallbacks="default",
                output_config={"effort": "medium"},
                system=SYSTEM_PROMPT + ANTHROPIC_ENDING,
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
            return normalize_report(dict(report.input))
        messages.append({"role": "assistant", "content": response.content})
        if response.stop_reason == "pause_turn":
            continue  # la búsqueda web sigue en curso: reenviar para continuar
        messages.append({"role": "user", "content": "Reporta el resultado con la herramienta report_device."})
    raise EnrichError("El modelo no reportó un resultado")


# --- OpenRouter --------------------------------------------------------------
def identify_openrouter(facts: dict, api_key: str, model: str = OPENROUTER_DEFAULT_MODEL, engine: str = "exa",
                        http: httpx.Client | None = None) -> dict:
    """Cualquier modelo de OpenRouter con el plugin de búsqueda web y salida JSON con esquema.

    - provider.data_collection="deny": solo proveedores que no guardan ni entrenan con los datos.
    - Si el modelo/proveedor no acepta response_format, se reintenta pidiendo el JSON en el prompt.
    """
    if not api_key:
        raise EnrichError("Falta la clave de OpenRouter (Configuración › Búsqueda en internet)")
    plugin = {"id": "web", "max_results": 5}
    if engine in ("exa", "native"):
        plugin["engine"] = engine
    base = {
        "model": model,
        "messages": [{"role": "system", "content": SYSTEM_PROMPT + JSON_ENDING},
                     {"role": "user", "content": _user_message(facts)}],
        "plugins": [plugin],
        "max_tokens": 4000,
    }
    structured = {
        **base,
        "response_format": {"type": "json_schema", "json_schema": {
            "name": "report_device", "strict": True, "schema": REPORT_TOOL["input_schema"]}},
        "provider": {"data_collection": "deny", "require_parameters": True},
    }
    headers = {"Authorization": f"Bearer {api_key}", "HTTP-Referer": "https://github.com/ellaguno/iureTI",
               "X-Title": "iureTI Discovery"}
    client = http or httpx.Client(timeout=120.0)
    try:
        data = _openrouter_post(client, headers, structured)
        if data is None:  # ningún proveedor soporta el esquema: JSON por prompt
            data = _openrouter_post(client, headers, {**base, "provider": {"data_collection": "deny"}}, final=True)
    finally:
        if http is None:
            client.close()
    choice = (data.get("choices") or [{}])[0]
    message = choice.get("message") or {}
    report = normalize_report(parse_json_text(message.get("content") or ""))
    # Si el modelo no dio ficha, la primera fuente citada sirve para buscar la foto (og:image)
    cited = [a.get("url_citation", {}).get("url", "") for a in message.get("annotations") or []]
    report["sources"] = [u for u in cited if u][:5]
    if not report["product_url"] and report["sources"]:
        report["product_url_hint"] = report["sources"][0]
    usage = data.get("usage") or {}
    if usage.get("cost") is not None:
        report["cost_usd"] = usage["cost"]
    report["model_used"] = data.get("model", model)
    return report


def _openrouter_post(client: httpx.Client, headers: dict, body: dict, final: bool = False) -> dict | None:
    try:
        resp = client.post(OPENROUTER_URL, json=body, headers=headers)
    except httpx.HTTPError as exc:
        raise EnrichError(f"Sin conexión con OpenRouter: {exc}") from exc
    if resp.status_code == 200:
        data = resp.json()
        if data.get("error"):
            raise EnrichError(f"OpenRouter: {data['error'].get('message', data['error'])}")
        return data
    try:
        message = resp.json().get("error", {}).get("message", resp.text[:200])
    except ValueError:
        message = resp.text[:200]
    if resp.status_code == 401:
        raise EnrichError("Clave de OpenRouter inválida (Configuración › Búsqueda en internet)")
    if resp.status_code == 402:
        raise EnrichError("Sin créditos en OpenRouter (openrouter.ai/settings/credits)")
    if resp.status_code == 429:
        raise EnrichError("Límite de uso de OpenRouter alcanzado; intenta más tarde")
    if resp.status_code in (400, 404) and not final:
        return None  # p.ej. «No endpoints found that can handle the requested parameters»
    raise EnrichError(f"OpenRouter respondió {resp.status_code}: {message}")


# ---------------------------------------------------------------------------
# Imagen del producto
# ---------------------------------------------------------------------------
# Una URL que dio la IA o que anunció un equipo no es de fiar: puede apuntar a la red interna o,
# tras validarla, redirigir a ella. Por eso se resuelve el host, se exige que sea público, se conecta
# a esa IP fija y se validan TODOS los saltos (security.resolve_safe_target + MAX_REDIRECTS).
MAX_REDIRECTS = 4


def is_public_url(url: str) -> bool:
    return security.resolve_safe_target(url) is not None


_OG_IMAGE = re.compile(
    r'<meta[^>]+(?:property|name)=["\'](?:og:image|twitter:image)(?::src)?["\'][^>]*content=["\']([^"\']+)'
    r'|<meta[^>]+content=["\']([^"\']+)["\'][^>]*(?:property|name)=["\'](?:og:image|twitter:image)', re.I)


def _safe_get(client: httpx.Client, url: str, max_bytes: int) -> tuple[httpx.Response, bytes] | None:
    """GET siguiendo redirecciones a mano, validando cada destino contra SSRF. (resp_final, cuerpo) o None."""
    for _ in range(MAX_REDIRECTS + 1):
        target = security.resolve_safe_target(url)
        if target is None:
            return None
        ip, host = target
        parts = urlsplit(url)
        connect_url = f"{parts.scheme}://{ip}" + (f":{parts.port}" if parts.port else "") + (parts.path or "/")
        if parts.query:
            connect_url += "?" + parts.query
        try:
            with client.stream("GET", connect_url, headers={"Host": host}, follow_redirects=False) as resp:
                if resp.is_redirect and resp.headers.get("location"):
                    url = str(httpx.URL(url).join(resp.headers["location"]))
                    continue
                if resp.status_code != 200:
                    return None
                body = b""
                for chunk in resp.iter_bytes():
                    body += chunk
                    if len(body) > max_bytes:
                        break
                return resp, body
        except httpx.HTTPError:
            return None
    return None


def page_image(client: httpx.Client, page_url: str) -> str:
    got = _safe_get(client, page_url, MAX_PAGE_BYTES)
    if got is None or "html" not in got[0].headers.get("content-type", ""):
        return ""
    m = _OG_IMAGE.search(got[1].decode("utf-8", errors="replace"))
    return urljoin(page_url, m.group(1) or m.group(2)) if m else ""


EXTENSIONS = {"image/jpeg": ".jpg", "image/png": ".png", "image/webp": ".webp", "image/gif": ".gif"}


def images_dir() -> Path:
    path = cache_dir() / "images"
    path.mkdir(parents=True, exist_ok=True)
    return path


def download_image(client: httpx.Client, url: str) -> str:
    """Descarga y valida la imagen; devuelve el nombre del archivo en caché o ''."""
    if not url:
        return ""
    got = _safe_get(client, url, MAX_IMAGE_BYTES)
    if got is None:
        return ""
    resp, data = got
    ctype = resp.headers.get("content-type", "").split(";")[0].strip().lower()
    if ctype not in EXTENSIONS or len(data) < 1024 or len(data) > MAX_IMAGE_BYTES:
        return ""
    filename = hashlib.sha1(url.encode()).hexdigest()[:20] + EXTENSIONS[ctype]
    (images_dir() / filename).write_bytes(data)
    return filename


def resolve_image(result: dict) -> tuple[str, str]:
    """(url, archivo) de la primera imagen válida: la que dio la búsqueda o la og:image de la página del producto."""
    headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) iureti-discovery"}
    with httpx.Client(timeout=10.0, follow_redirects=False, headers=headers) as client:
        candidates = [result.get("image_url", "")]
        for page in (result.get("product_url"), result.get("product_url_hint")):
            if page:
                candidates.append(page_image(client, page))
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
