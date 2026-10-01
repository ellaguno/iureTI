"""Interfaz web local de la sonda (FastAPI)."""

from __future__ import annotations

import asyncio
import secrets
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from pydantic import BaseModel

import re

from .. import __version__, enrich, netutil, security, service
from ..agent import Agent, parse_window, version_tuple
from ..models import DEVICE_TYPES
from ..oui import OuiDatabase
from ..runtime import Busy, Runtime
from ..store import Store
from ..sync import DEVICE_TYPE_LABELS, SyncError, build_batch, to_import_csv

STATIC = Path(__file__).parent / "static"
SECRET_FIELDS = ("community", "auth_key", "priv_key")
MASK = "********"

# Páginas estáticas servibles (no sensibles); todo lo demás bajo /api exige la cabecera propia.
STATIC_FILES = {"/": "index.html", "/app.js": "app.js"}
CONTENT_SECURITY_POLICY = (
    "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
    "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)
SECURITY_HEADERS = {
    "Content-Security-Policy": CONTENT_SECURITY_POLICY,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cache-Control": "no-store",
}


class ScanRequest(BaseModel):
    targets: list[str]
    snmp: bool = True


class DeleteRequest(BaseModel):
    ids: list[str]


TOP_SECRETS = ("api_token", "anthropic_api_key", "openrouter_api_key")


def _mask_settings(settings: dict) -> dict:
    out = dict(settings)
    out.pop("ui_token", None)  # el token de la interfaz nunca sale por la API
    for key in TOP_SECRETS:
        out[key] = MASK if settings.get(key) else ""
    out["snmp_credentials"] = [
        {**c, **{f: MASK for f in SECRET_FIELDS if c.get(f)}} for c in settings.get("snmp_credentials", [])
    ]
    return out


def _unmask_settings(new: dict, current: dict) -> dict:
    """Los campos secretos que llegan enmascarados conservan su valor guardado."""
    new.pop("ui_token", None)  # no es editable por la API
    # A1: si cambia la URL de iurefficient, el token NO se reutiliza (iría a parar al destino nuevo).
    if "api_url" in new and (new.get("api_url") or "").rstrip("/") != (current.get("api_url") or "").rstrip("/"):
        if new.get("api_token") == MASK:
            new["api_token"] = ""
    for key in TOP_SECRETS:
        if new.get(key) == MASK:
            new[key] = current.get(key, "")
    if "snmp_credentials" in new:
        old = {c["name"]: c for c in current.get("snmp_credentials", [])}
        for cred in new["snmp_credentials"]:
            for f in SECRET_FIELDS:
                if cred.get(f) == MASK:
                    cred[f] = old.get(cred.get("name"), {}).get(f, "")
    return new


def _url_ok(url: str) -> bool:
    """iurefficient debe ser https, salvo http a una dirección local/privada (on-prem en la misma red)."""
    parts = urlsplit(url)
    if parts.scheme == "https":
        return True
    if parts.scheme == "http" and parts.hostname:
        return parts.hostname in security.LOOPBACK_HOSTS or security.is_literal_private_ip(parts.hostname)
    return False


def create_app(db_path: str | None = None, agent: bool = False,
               bind_host: str = "127.0.0.1", port: int = 8765) -> FastAPI:
    store = Store(db_path)
    rt = Runtime(store, OuiDatabase())
    probe_agent = Agent(rt) if agent else None

    # Token de interfaz: solo se EXIGE cuando la sonda se expone fuera de loopback. Se genera una vez.
    require_token = not security.is_loopback_bind(bind_host)
    ui_token = store.get_settings().get("ui_token") or ""
    if require_token and not ui_token:
        ui_token = security.new_ui_token()
        store.update_settings({"ui_token": ui_token})

    @asynccontextmanager
    async def lifespan(_app):
        task = asyncio.create_task(probe_agent.run()) if probe_agent else None
        yield
        if task:
            task.cancel()

    # /docs y /openapi.json quedan desactivados: no exponer el mapa de la API.
    app = FastAPI(title="iureTI Discovery", version=__version__, lifespan=lifespan,
                  docs_url=None, redoc_url=None, openapi_url=None)

    wildcard = bind_host in ("0.0.0.0", "::")

    @app.middleware("http")
    async def guard(request: Request, call_next):
        path = request.url.path
        # 1) Host allowlist: defensa contra DNS rebinding (un sitio cuyo dominio apunta a 127.0.0.1).
        #    Con enlace comodín (0.0.0.0) no se puede enumerar la IP pública: ahí manda el token.
        if not wildcard and not security.host_is_allowed(request.headers.get("host", ""), bind_host, port):
            return JSONResponse({"detail": "Host no permitido"}, status_code=400)
        is_api = path.startswith("/api/")
        is_image = path.startswith("/api/images/")
        if is_api and not is_image:
            # 2) Origen: ninguna página de otro sitio puede llamar a la API.
            origin = request.headers.get("origin")
            if origin:
                oh = urlsplit(origin).netloc.lower()
                if oh not in {h.lower() for h in security.allowed_hosts(bind_host, port)}:
                    return JSONResponse({"detail": "Origen no permitido"}, status_code=403)
            # 3) Cabecera propia: un formulario/imagen de otro sitio no puede ponerla (bloquea CSRF).
            if request.headers.get("x-iureti-ui") != "1":
                return JSONResponse({"detail": "Falta la cabecera de la interfaz"}, status_code=403)
            # 4) Token, solo si la interfaz está expuesta en la red.
            if require_token:
                sent = request.headers.get("x-iureti-token") or request.query_params.get("token") or ""
                if not secrets.compare_digest(sent, ui_token):
                    return JSONResponse({"detail": "Token de interfaz inválido"}, status_code=401)
        elif is_image and require_token:
            if not secrets.compare_digest(request.query_params.get("token") or "", ui_token):
                return JSONResponse({"detail": "Token de interfaz inválido"}, status_code=401)
        response = await call_next(request)
        for key, value in SECURITY_HEADERS.items():
            response.headers.setdefault(key, value)
        return response

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(STATIC / "index.html")

    @app.get("/app.js", include_in_schema=False)
    def app_js():
        return FileResponse(STATIC / "app.js", media_type="application/javascript")

    @app.get("/api/status")
    def status():
        settings = store.get_settings()
        agent_state = dict(probe_agent.state) if probe_agent else None
        if agent_state:
            latest = agent_state.get("latest_version") or ""
            agent_state["update_available"] = bool(latest) and version_tuple(latest) > version_tuple(__version__)
        return {
            "version": __version__,
            "oui_available": rt.oui.available,
            "networks": [n.__dict__ for n in sorted(netutil.local_networks(), key=lambda n: n.virtual)],
            "scan": rt.progress.to_dict(),
            "last_summary": rt.summary,
            "counts": rt.counts(),
            "device_types": {t: DEVICE_TYPE_LABELS[t] for t in DEVICE_TYPES},
            "sync_configured": bool(settings.get("api_url")),
            "enrich_enabled": bool(settings.get("enrich_enabled")),
            "enrich": rt.enrich_job,
            "openrouter_models": enrich.OPENROUTER_MODELS,
            "managed": bool(settings.get("managed")),
            "schedule": {"interval_minutes": settings.get("schedule_interval_minutes", 0),
                         "window": settings.get("schedule_window", "")},
            "agent": agent_state,
            "last_sync": rt.last_sync,
        }

    @app.get("/api/settings")
    def get_settings():
        return _mask_settings(store.get_settings())

    @app.put("/api/settings")
    def put_settings(values: dict):
        if values.get("enrich_provider", "openrouter") not in ("openrouter", "anthropic"):
            raise HTTPException(400, "Proveedor inválido (openrouter o anthropic)")
        if values.get("openrouter_web_engine", "exa") not in enrich.WEB_ENGINES:
            raise HTTPException(400, "Motor de búsqueda inválido (exa, native o auto)")
        if values.get("schedule_window") and parse_window(values["schedule_window"]) is None:
            raise HTTPException(400, "Ventana inválida: usa HH:MM-HH:MM (p.ej. 01:00-05:00)")
        url = (values.get("api_url") or "").strip()
        if url and not _url_ok(url):
            raise HTTPException(400, "La URL de iurefficient debe ser https:// (o http:// solo a una dirección local)")
        if "allowed_networks" in values:
            nets = values.get("allowed_networks") or []
            if not isinstance(nets, list) or len(security.parse_networks(nets)) != len(nets):
                raise HTTPException(400, "Redes permitidas inválidas: usa CIDR (p.ej. 192.168.1.0/24)")
        for key, lo, hi in (("concurrency", 8, security.MAX_CONCURRENCY),
                            ("heartbeat_seconds", security.MIN_HEARTBEAT, security.MAX_HEARTBEAT)):
            if key in values and not (isinstance(values[key], int) and lo <= values[key] <= hi):
                raise HTTPException(400, f"{key} fuera de rango ({lo}–{hi})")
        if "tcp_timeout" in values:
            t = values["tcp_timeout"]
            if not (isinstance(t, (int, float)) and security.MIN_TCP_TIMEOUT <= t <= security.MAX_TCP_TIMEOUT):
                raise HTTPException(400, f"tcp_timeout fuera de rango ({security.MIN_TCP_TIMEOUT}–{security.MAX_TCP_TIMEOUT})")
        for cred in values.get("snmp_credentials", []):
            if not cred.get("name"):
                raise HTTPException(400, "Cada credencial SNMP necesita un nombre")
            if cred.get("version") not in ("2c", "3"):
                raise HTTPException(400, "Versión SNMP inválida (2c o 3)")
            if cred.get("networks") and len(security.parse_networks(cred["networks"])) != len(cred["networks"]):
                raise HTTPException(400, f"Subredes inválidas en la credencial «{cred['name']}»")
        return _mask_settings(store.update_settings(_unmask_settings(values, store.get_settings())))

    @app.post("/api/scans")
    async def start_scan(req: ScanRequest):
        try:
            rt.start_scan(req.targets, use_snmp=req.snmp)
        except Busy as exc:
            raise HTTPException(409, str(exc))
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        return rt.progress.to_dict()

    @app.post("/api/scans/cancel")
    def cancel_scan():
        rt.cancel_scan()
        return rt.progress.to_dict()

    @app.get("/api/scans")
    def list_scans():
        return store.list_scans()

    @app.get("/api/assets")
    def list_assets():
        assets = sorted(store.list_assets(), key=lambda a: tuple(int(x) for x in (a.ips or ["0.0.0.0"])[0].split(".")))
        return [a.to_dict() for a in assets]

    @app.post("/api/assets/delete")
    def delete_assets(req: DeleteRequest):
        """Olvida activos localmente (p.ej. un rango escaneado por error). No afecta a iurefficient."""
        return {"deleted": store.delete_assets(req.ids)}

    @app.post("/api/assets/{asset_id}/enrich")
    async def enrich_one(asset_id: str, force: bool = False):
        try:
            return await asyncio.to_thread(service.enrich_asset, store, asset_id, force)
        except enrich.EnrichError as exc:
            raise HTTPException(400, str(exc))

    @app.post("/api/enrich")
    async def enrich_bulk(only_missing: bool = True):
        try:
            rt.start_enrich(only_missing)
        except Busy as exc:
            raise HTTPException(409, str(exc))
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        return rt.enrich_job

    @app.get("/api/images/{filename}", include_in_schema=False)
    def image(filename: str):
        if not re.fullmatch(r"[0-9a-f]{20}\.(jpg|png|webp|gif)", filename):
            raise HTTPException(404)
        path = enrich.images_dir() / filename
        if not path.exists():
            raise HTTPException(404)
        return FileResponse(path, headers={"Cache-Control": "max-age=86400"})

    @app.get("/api/export.json")
    def export_json():
        scans = store.list_scans(1)
        batch = build_batch(store.list_assets(), store.get_settings(), scans[0] if scans else None)
        return JSONResponse(batch, headers={"Content-Disposition": 'attachment; filename="iureti-activos.json"'})

    @app.get("/api/export.csv")
    def export_csv():
        return Response(
            to_import_csv(store.list_assets()),
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": 'attachment; filename="iureti-inventario-importar.csv"'},
        )

    @app.post("/api/sync")
    async def sync(only_changed: bool = False):
        try:
            return await rt.sync(only_changed)
        except SyncError as exc:
            raise HTTPException(502, str(exc))

    @app.post("/api/oui/update")
    async def update_oui():
        try:
            count = await asyncio.to_thread(rt.oui.update)
        except Exception as exc:
            raise HTTPException(502, f"No se pudo descargar la base OUI: {exc}")
        return {"entries": count}

    return app
