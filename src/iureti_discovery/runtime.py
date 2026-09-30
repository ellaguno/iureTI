"""Estado vivo de la sonda: un solo escaneo, una sola búsqueda en internet y el último envío a la vez.

Lo comparten la interfaz web y el agente (modo servicio), para que nunca corran dos escaneos juntos.
"""

from __future__ import annotations

import asyncio

from . import enrich, netutil, service
from .models import utcnow
from .oui import OuiDatabase
from .scanner import ScanProgress
from .store import Store
from .sync import SyncError

FATAL_ENRICH_WORDS = ("Clave", "clave", "desactivada", "créditos")


class Busy(RuntimeError):
    pass


class Runtime:
    def __init__(self, store: Store, oui: OuiDatabase | None = None):
        self.store = store
        self.oui = oui or OuiDatabase()
        self.progress = ScanProgress()
        self.scanner = None
        self.scan_task: asyncio.Task | None = None
        self.summary: dict | None = None
        self.enrich_job = {"running": False, "total": 0, "done": 0, "errors": [], "cached": 0}
        self.last_sync: dict = {}

    # --- escaneo ---------------------------------------------------------------
    def start_scan(self, targets: list[str], use_snmp: bool = True, remember: bool = True) -> asyncio.Task:
        if self.progress.running:
            raise Busy("Ya hay un escaneo en curso")
        if not targets:
            raise ValueError("Indica al menos un rango")
        netutil.expand_targets(targets)  # valida (ValueError)
        self.scanner = service.make_scanner(self.store, targets, progress=self.progress, oui=self.oui,
                                            use_snmp=use_snmp)
        if remember:
            self.store.update_settings({"targets": targets})
        self.progress.started_at, self.progress.finished_at, self.progress.phase = utcnow(), "", "iniciando"

        async def job():
            try:
                self.summary = await service.run_scan(self.store, self.scanner)
            except Exception as exc:  # el error queda también en progress.error
                self.summary = {"error": str(exc)}
            return self.summary

        self.scan_task = asyncio.create_task(job())
        return self.scan_task

    async def scan(self, targets: list[str], use_snmp: bool = True, remember: bool = True) -> dict:
        return await self.start_scan(targets, use_snmp, remember)

    def cancel_scan(self) -> None:
        if self.scanner and self.progress.running:
            self.scanner.cancel()

    # --- envío -------------------------------------------------------------------
    async def sync(self, only_changed: bool = False) -> dict:
        try:
            result = await asyncio.to_thread(service.sync_all, self.store, only_changed)
        except SyncError as exc:
            self.last_sync = {"at": utcnow(), "sent": 0, "error": str(exc)}
            raise
        self.last_sync = {"at": utcnow(), "sent": result["sent"], "error": ""}
        return result

    # --- búsqueda en internet ----------------------------------------------------
    def start_enrich(self, only_missing: bool = True) -> asyncio.Task:
        job = self.enrich_job
        if job["running"]:
            raise Busy("Ya hay una búsqueda en curso")
        if not self.store.get_settings().get("enrich_enabled"):
            raise ValueError("La búsqueda en internet está desactivada (Configuración)")
        ids = service.enrich_candidates(self.store, only_missing)
        job.update(running=True, total=len(ids), done=0, errors=[], cached=0)

        async def run():
            try:
                for asset_id in ids:
                    try:
                        r = await asyncio.to_thread(service.enrich_asset, self.store, asset_id)
                        job["cached"] += r["cached"]
                    except enrich.EnrichError as exc:
                        job["errors"].append(str(exc))
                        if any(w in str(exc) for w in FATAL_ENRICH_WORDS):
                            break  # no tiene caso seguir
                    job["done"] += 1
            finally:
                job["running"] = False
            return dict(job)

        return asyncio.create_task(run())

    # --- resumen -----------------------------------------------------------------
    def counts(self) -> dict:
        assets = self.store.list_assets()
        return {"total": len(assets),
                "unsynced": sum(1 for a in assets if not a.synced_at or a.synced_at < a.last_seen)}
