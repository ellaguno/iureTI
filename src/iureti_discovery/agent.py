"""Modo servicio: heartbeat con iurefficient, configuración remota, órdenes y escaneos programados.

La sonda solo hace conexiones salientes. Contrato en docs/04-api-ingesta.md
(«Gestión de sondas: POST /api/plugins/inventory/discovery/heartbeat»).
"""

from __future__ import annotations

import asyncio
import logging
import os
import platform
import socket
from datetime import datetime, timedelta

import httpx

from . import __version__, localhost, netutil
from .runtime import Busy, Runtime
from .sync import SyncError

log = logging.getLogger("iureti.agent")
HEARTBEAT_PATH = "/api/plugins/inventory/discovery/heartbeat"
TICK_SECONDS = 30
CAPABILITIES = ["sweep", "ports", "oui", "snmp", "mdns", "ssdp", "http", "netbios", "enrich"]
COLLECTOR_SETTINGS = {"snmp": None, "mdns": "use_mdns", "ssdp": "use_ssdp", "http": "use_http",
                      "netbios": "use_netbios", "ping": "use_ping", "dns": "resolve_dns"}


def parse_window(window: str) -> tuple[int, int] | None:
    """'01:00-05:00' → (60, 300) minutos del día; None si vacío o inválido."""
    try:
        start, end = (part.strip() for part in window.split("-"))
        to_min = lambda hhmm: int(hhmm.split(":")[0]) * 60 + int(hhmm.split(":")[1])  # noqa: E731
        return to_min(start), to_min(end)
    except (ValueError, IndexError, AttributeError):
        return None


def in_window(window: str, now: datetime) -> bool:
    bounds = parse_window(window) if window else None
    if bounds is None:
        return True
    start, end = bounds
    minute = now.hour * 60 + now.minute
    return start <= minute < end if start <= end else (minute >= start or minute < end)  # cruza medianoche


def version_tuple(version: str) -> tuple:
    return tuple(int(x) for x in version.split(".") if x.isdigit())


class Agent:
    def __init__(self, rt: Runtime, http: httpx.AsyncClient | None = None, now=datetime.now):
        self.rt = rt
        self.http = http
        self.now = now
        self.acks: list[dict] = []
        self.commands: asyncio.Queue = asyncio.Queue()
        self.next_heartbeat = datetime.min
        self.state = {"last_heartbeat": "", "error": "", "latest_version": "", "connected": False,
                      "last_scheduled_scan": ""}

    # --- ciclo principal ---------------------------------------------------------
    async def run(self) -> None:
        log.info("agente iniciado")
        if not self.rt.oui.available:  # primera ejecución del servicio: base de fabricantes
            try:
                log.info("descargando base OUI: %s fabricantes", await asyncio.to_thread(self.rt.oui.update))
            except Exception as exc:
                log.warning("no se pudo descargar la base OUI (se reintenta al reiniciar): %s", exc)
        while True:
            try:
                await self.tick()
            except Exception:  # el agente nunca debe morir por un error puntual
                log.exception("error en el ciclo del agente")
            await asyncio.sleep(TICK_SECONDS)

    async def tick(self) -> None:
        settings = self.rt.store.get_settings()
        if settings.get("api_url") and settings.get("api_token") and self.now() >= self.next_heartbeat:
            await self.heartbeat()
        while not self.commands.empty():
            await self.execute(self.commands.get_nowait())
        if self.schedule_due():
            await self.scheduled_scan()

    # --- heartbeat ---------------------------------------------------------------
    def payload(self) -> dict:
        s = self.rt.store.get_settings()
        scans = self.rt.store.list_scans(1)
        last = scans[0] if scans else {}
        me = localhost.describe()
        counts = self.rt.counts()
        return {
            "probe": {"id": s.get("probe_id") or socket.gethostname(), "version": __version__,
                      "site": s.get("site", ""), "hostname": socket.gethostname(), "os": me["os"],
                      "arch": platform.machine(), "install": os.environ.get("IURETI_INSTALL", "")},
            "status": {
                "state": "scanning" if self.rt.progress.running else "idle",
                "assets": counts["total"],
                "unsynced": counts["unsynced"],
                "last_scan": {k: last.get(k) for k in ("started_at", "finished_at", "targets", "alive",
                                                       "new_assets", "error")} if last else None,
                "last_sync": self.rt.last_sync or None,
            },
            "networks": [{"interface": n.interface, "network": n.network}
                         for n in netutil.local_networks() if not n.virtual],
            "capabilities": CAPABILITIES,
            "config_version": s.get("config_version", ""),
            "acks": list(self.acks),
        }

    async def heartbeat(self) -> None:
        s = self.rt.store.get_settings()
        url = s["api_url"].rstrip("/") + HEARTBEAT_PATH
        interval = int(s.get("heartbeat_seconds") or 300)
        self.next_heartbeat = self.now() + timedelta(seconds=interval)
        sent_acks = list(self.acks)
        client = self.http or httpx.AsyncClient(timeout=30.0)
        try:
            resp = await client.post(url, json=self.payload(), headers={"Authorization": f"Bearer {s['api_token']}"})
        except httpx.HTTPError as exc:
            self._fail(f"Sin conexión con iurefficient: {exc}")
            return
        finally:
            if self.http is None:
                await client.aclose()
        if resp.status_code == 404:
            self._fail("iurefficient aún no tiene gestión de sondas (404): se opera en modo local")
            return
        if resp.status_code in (401, 403):
            self._fail("Token de sonda rechazado por iurefficient")
            return
        if resp.status_code >= 400:
            self._fail(f"iurefficient respondió {resp.status_code}")
            return
        data = resp.json() if resp.content else {}
        self.acks = [a for a in self.acks if a not in sent_acks]  # entregadas
        self.state.update(last_heartbeat=datetime.now().astimezone().isoformat(timespec="seconds"), error="",
                          connected=True, latest_version=data.get("latest_version", ""))
        if data.get("config") is not None:
            self.apply_config(data["config"], data.get("config_version", ""))
        for command in data.get("commands") or []:
            self.commands.put_nowait(command)

    def _fail(self, message: str) -> None:
        log.warning(message)
        self.state.update(error=message, connected=False)

    def apply_config(self, config: dict, version: str) -> None:
        updates: dict = {"managed": True, "config_version": version}
        if isinstance(config.get("targets"), list):
            try:
                netutil.expand_targets(config["targets"])
                updates["targets"] = config["targets"]
            except ValueError as exc:
                log.warning("rangos inválidos recibidos: %s", exc)
        schedule = config.get("schedule") or {}
        if "interval_minutes" in schedule:
            updates["schedule_interval_minutes"] = int(schedule["interval_minutes"] or 0)
        if "window" in schedule:
            updates["schedule_window"] = schedule["window"] or ""
        for name, enabled in (config.get("collectors") or {}).items():
            if COLLECTOR_SETTINGS.get(name):
                updates[COLLECTOR_SETTINGS[name]] = bool(enabled)
        if "snmp" in (config.get("collectors") or {}):
            updates["snmp_enabled"] = bool(config["collectors"]["snmp"])
        for key in ("concurrency", "tcp_timeout", "auto_sync", "auto_enrich", "heartbeat_seconds"):
            if key in config:
                updates[key] = config[key]
        self.rt.store.update_settings(updates)
        log.info("configuración %s aplicada", version or "(sin versión)")

    # --- órdenes -----------------------------------------------------------------
    async def execute(self, command: dict) -> None:
        cid, kind, args = command.get("id", ""), command.get("type", ""), command.get("args") or {}
        try:
            if kind == "scan_now":
                s = self.rt.store.get_settings()
                summary = await self.rt.scan(args.get("targets") or s.get("targets") or [],
                                             use_snmp=s.get("snmp_enabled", True), remember=False)
                await self.after_scan()
                detail = summary.get("error") or f"{summary.get('observed', 0)} hosts vivos, {summary.get('new', 0)} nuevos"
                self.ack(cid, "failed" if summary.get("error") else "done", detail)
            elif kind == "sync_now":
                r = await self.rt.sync()
                self.ack(cid, "done", f"{r['sent']} activos enviados")
            elif kind == "enrich_now":
                job = await self.rt.start_enrich()
                self.ack(cid, "done", f"{job['done']}/{job['total']} buscados")
            elif kind == "forget_assets":
                self.ack(cid, "done", f"{self.rt.store.delete_assets(list(args.get('ids') or []))} olvidados")
            else:
                self.ack(cid, "ignored", f"orden desconocida: {kind}")
        except (Busy, ValueError, SyncError) as exc:
            self.ack(cid, "failed", str(exc))

    def ack(self, cid: str, status: str, detail: str = "") -> None:
        if cid:
            self.acks.append({"id": cid, "status": status, "detail": detail[:300]})

    # --- programación ------------------------------------------------------------
    def schedule_due(self) -> bool:
        s = self.rt.store.get_settings()
        interval = int(s.get("schedule_interval_minutes") or 0)
        if interval <= 0 or not s.get("targets") or self.rt.progress.running:
            return False
        now = self.now()
        if not in_window(s.get("schedule_window", ""), now):
            return False
        scans = self.rt.store.list_scans(1)
        if not scans or not scans[0].get("started_at"):
            return True
        last = datetime.fromisoformat(scans[0]["started_at"].replace("Z", "+00:00"))
        return now.astimezone() - last >= timedelta(minutes=interval)

    async def scheduled_scan(self) -> None:
        s = self.rt.store.get_settings()
        log.info("escaneo programado: %s", s["targets"])
        self.state["last_scheduled_scan"] = datetime.now().astimezone().isoformat(timespec="seconds")
        try:
            await self.rt.scan(s["targets"], use_snmp=s.get("snmp_enabled", True), remember=False)
        except (Busy, ValueError) as exc:
            log.warning("escaneo programado omitido: %s", exc)
            return
        await self.after_scan()

    async def after_scan(self) -> None:
        s = self.rt.store.get_settings()
        if s.get("auto_enrich") and s.get("enrich_enabled"):
            try:
                await self.rt.start_enrich()
            except (Busy, ValueError) as exc:
                log.warning("búsqueda en internet omitida: %s", exc)
        if s.get("auto_sync") and s.get("api_url") and s.get("api_token"):
            try:
                await self.rt.sync(only_changed=False)  # todo: mantiene last_seen al día en iurefficient
            except SyncError as exc:
                log.warning("envío fallido: %s", exc)
