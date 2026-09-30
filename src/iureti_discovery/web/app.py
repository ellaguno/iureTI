"""Interfaz web local de la sonda (FastAPI)."""

from __future__ import annotations

import asyncio
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse, Response
from pydantic import BaseModel

from .. import __version__, netutil, service
from ..models import DEVICE_TYPES, utcnow
from ..oui import OuiDatabase
from ..scanner import ScanProgress, Scanner
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


def _mask_settings(settings: dict) -> dict:
    out = dict(settings)
    out["api_token"] = MASK if settings.get("api_token") else ""
    out["snmp_credentials"] = [
        {**c, **{f: MASK for f in SECRET_FIELDS if c.get(f)}} for c in settings.get("snmp_credentials", [])
    ]
    return out


def _unmask_settings(new: dict, current: dict) -> dict:
    """Los campos secretos que llegan enmascarados conservan su valor guardado."""
    if new.get("api_token") == MASK:
        new["api_token"] = current.get("api_token", "")
    if "snmp_credentials" in new:
        old = {c["name"]: c for c in current.get("snmp_credentials", [])}
        for cred in new["snmp_credentials"]:
            for f in SECRET_FIELDS:
                if cred.get(f) == MASK:
                    cred[f] = old.get(cred.get("name"), {}).get(f, "")
    return new


def create_app(db_path: str | None = None) -> FastAPI:
    app = FastAPI(title="iureTI Discovery", version=__version__)
    store = Store(db_path)
    oui = OuiDatabase()
    progress = ScanProgress()
    state: dict = {"scanner": None, "task": None, "summary": None}

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(STATIC / "index.html")

    @app.get("/api/status")
    def status():
        assets = store.list_assets()
        counts = {"total": len(assets), "unsynced": sum(1 for a in assets if not a.synced_at or a.synced_at < a.last_seen)}
        return {
            "version": __version__,
            "oui_available": oui.available,
            "networks": [n.__dict__ for n in sorted(netutil.local_networks(), key=lambda n: n.virtual)],
            "scan": progress.to_dict(),
            "last_summary": state["summary"],
            "counts": counts,
            "device_types": {t: DEVICE_TYPE_LABELS[t] for t in DEVICE_TYPES},
            "sync_configured": bool(store.get_settings().get("api_url")),
        }

    @app.get("/api/settings")
    def get_settings():
        return _mask_settings(store.get_settings())

    @app.put("/api/settings")
    def put_settings(values: dict):
        for cred in values.get("snmp_credentials", []):
            if not cred.get("name"):
                raise HTTPException(400, "Cada credencial SNMP necesita un nombre")
            if cred.get("version") not in ("2c", "3"):
                raise HTTPException(400, "Versión SNMP inválida (2c o 3)")
        return _mask_settings(store.update_settings(_unmask_settings(values, store.get_settings())))

    @app.post("/api/scans")
    async def start_scan(req: ScanRequest):
        if progress.running:
            raise HTTPException(409, "Ya hay un escaneo en curso")
        try:
            netutil.expand_targets(req.targets)
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        if not req.targets:
            raise HTTPException(400, "Indica al menos un rango")
        scanner: Scanner = service.make_scanner(store, req.targets, progress=progress, oui=oui, use_snmp=req.snmp)
        store.update_settings({"targets": req.targets})
        progress.started_at, progress.finished_at, progress.phase = utcnow(), "", "iniciando"

        async def job():
            try:
                state["summary"] = await service.run_scan(store, scanner)
            except Exception as exc:  # el error queda en progress.error
                state["summary"] = {"error": str(exc)}

        state["scanner"], state["task"] = scanner, asyncio.create_task(job())
        return progress.to_dict()

    @app.post("/api/scans/cancel")
    def cancel_scan():
        if state["scanner"] and progress.running:
            state["scanner"].cancel()
        return progress.to_dict()

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
            return await asyncio.to_thread(service.sync_all, store, only_changed)
        except SyncError as exc:
            raise HTTPException(502, str(exc))

    @app.post("/api/oui/update")
    async def update_oui():
        try:
            count = await asyncio.to_thread(oui.update)
        except Exception as exc:
            raise HTTPException(502, f"No se pudo descargar la base OUI: {exc}")
        return {"entries": count}

    return app
