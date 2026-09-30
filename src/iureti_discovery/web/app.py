"""Interfaz web local de la sonda (FastAPI)."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse, Response
from pydantic import BaseModel

import re

from .. import __version__, enrich, netutil, service
from ..agent import Agent, parse_window, version_tuple
from ..models import DEVICE_TYPES
from ..oui import OuiDatabase
from ..runtime import Busy, Runtime
from ..store import Store
from ..sync import DEVICE_TYPE_LABELS, SyncError, build_batch, to_import_csv

STATIC = Path(__file__).parent / "static"
SECRET_FIELDS = ("community", "auth_key", "priv_key")
MASK = "********"


class ScanRequest(BaseModel):
    targets: list[str]
    snmp: bool = True


class DeleteRequest(BaseModel):
    ids: list[str]


TOP_SECRETS = ("api_token", "anthropic_api_key", "openrouter_api_key")


def _mask_settings(settings: dict) -> dict:
    out = dict(settings)
    for key in TOP_SECRETS:
        out[key] = MASK if settings.get(key) else ""
    out["snmp_credentials"] = [
        {**c, **{f: MASK for f in SECRET_FIELDS if c.get(f)}} for c in settings.get("snmp_credentials", [])
    ]
    return out


def _unmask_settings(new: dict, current: dict) -> dict:
    """Los campos secretos que llegan enmascarados conservan su valor guardado."""
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


def create_app(db_path: str | None = None, agent: bool = False) -> FastAPI:
    store = Store(db_path)
    rt = Runtime(store, OuiDatabase())
    probe_agent = Agent(rt) if agent else None

    @asynccontextmanager
    async def lifespan(_app):
        task = asyncio.create_task(probe_agent.run()) if probe_agent else None
        yield
        if task:
            task.cancel()

    app = FastAPI(title="iureTI Discovery", version=__version__, lifespan=lifespan)

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(STATIC / "index.html")

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
        for cred in values.get("snmp_credentials", []):
            if not cred.get("name"):
                raise HTTPException(400, "Cada credencial SNMP necesita un nombre")
            if cred.get("version") not in ("2c", "3"):
                raise HTTPException(400, "Versión SNMP inválida (2c o 3)")
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
