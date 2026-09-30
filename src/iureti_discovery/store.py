"""Persistencia local en SQLite."""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from pathlib import Path

from .models import Asset

SCHEMA = """
CREATE TABLE IF NOT EXISTS assets (
    id TEXT PRIMARY KEY,
    fingerprint TEXT NOT NULL,
    data TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT, finished_at TEXT, targets TEXT, phase TEXT,
    alive INTEGER, new_assets INTEGER, error TEXT
);
CREATE TABLE IF NOT EXISTS enrichment (
    key TEXT PRIMARY KEY,
    data TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""

DEFAULT_SETTINGS = {
    "probe_id": "",
    "site": "",
    "targets": [],
    "snmp_credentials": [],  # dicts de SnmpCredential (incluye secretos: la BD tiene permisos 600)
    "snmp_enabled": True,  # consultar SNMP en escaneos programados / remotos
    "api_url": "",
    "api_token": "",
    "concurrency": 256,
    "tcp_timeout": 0.8,
    "use_ping": True,
    "resolve_dns": True,
    "use_mdns": True,
    "use_ssdp": True,
    "use_http": True,
    "use_netbios": True,
    # Búsqueda en internet. Desactivada hasta que se configure.
    "enrich_enabled": False,
    "enrich_provider": "openrouter",  # openrouter | anthropic
    "openrouter_api_key": "",  # vacío = variable OPENROUTER_API_KEY
    "openrouter_model": "google/gemini-3.1-flash-lite",
    "openrouter_web_engine": "exa",  # exa | native | auto
    "anthropic_api_key": "",  # vacío = ANTHROPIC_API_KEY o perfil de `ant auth login`
    "anthropic_model": "claude-opus-5-5",
    # Operación continua (servicio): programación local o recibida de iurefficient
    "managed": False,  # True tras `enroll`: la configuración la manda iurefficient
    "heartbeat_seconds": 300,
    "config_version": "",
    "schedule_interval_minutes": 0,  # 0 = sin escaneos programados
    "schedule_window": "",  # "01:00-05:00" hora local; "" = cualquier hora
    "auto_sync": True,  # enviar a iurefficient después de cada escaneo programado
    "auto_enrich": False,  # buscar en internet los productos nuevos después de cada escaneo
}


def default_db_path() -> Path:
    if os.environ.get("IURETI_DB"):  # el servicio usa /var/lib/iureti/iureti.db
        return Path(os.environ["IURETI_DB"])
    base = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
    return Path(base) / "iureti-discovery" / "iureti.db"


class Store:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else default_db_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        new = not self.path.exists()
        self._lock = threading.Lock()
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.executescript(SCHEMA)
        if new:
            os.chmod(self.path, 0o600)

    # --- activos -----------------------------------------------------------
    def list_assets(self) -> list[Asset]:
        with self._lock:
            rows = self.conn.execute("SELECT data FROM assets").fetchall()
        return [Asset.from_dict(json.loads(r[0])) for r in rows]

    def get_asset(self, asset_id: str) -> Asset | None:
        with self._lock:
            row = self.conn.execute("SELECT data FROM assets WHERE id = ?", (asset_id,)).fetchone()
        return Asset.from_dict(json.loads(row[0])) if row else None

    def save_assets(self, assets: list[Asset]) -> None:
        with self._lock, self.conn:
            self.conn.executemany(
                "INSERT INTO assets (id, fingerprint, data) VALUES (?, ?, ?) "
                "ON CONFLICT(id) DO UPDATE SET fingerprint=excluded.fingerprint, data=excluded.data",
                [(a.id, a.fingerprint, json.dumps(a.to_dict())) for a in assets],
            )

    def delete_assets(self, asset_ids: list[str]) -> int:
        with self._lock, self.conn:
            cur = self.conn.executemany("DELETE FROM assets WHERE id = ?", [(i,) for i in asset_ids])
            return cur.rowcount

    # --- escaneos ----------------------------------------------------------
    def log_scan(self, progress: dict, new_assets: int) -> None:
        with self._lock, self.conn:
            self.conn.execute(
                "INSERT INTO scans (started_at, finished_at, targets, phase, alive, new_assets, error) VALUES (?,?,?,?,?,?,?)",
                (progress["started_at"], progress["finished_at"], json.dumps(progress["targets"]),
                 progress["phase"], progress["alive"], new_assets, progress["error"]),
            )

    def list_scans(self, limit: int = 20) -> list[dict]:
        with self._lock:
            cur = self.conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,))
            cols = [c[0] for c in cur.description]
            rows = [dict(zip(cols, r)) for r in cur.fetchall()]
        for r in rows:
            r["targets"] = json.loads(r["targets"] or "[]")
        return rows

    # --- caché de enriquecimiento (por huella de producto) ------------------
    def get_enrichment(self, key: str) -> dict | None:
        with self._lock:
            row = self.conn.execute("SELECT data FROM enrichment WHERE key = ?", (key,)).fetchone()
        return json.loads(row[0]) if row else None

    def save_enrichment(self, key: str, data: dict, created_at: str) -> None:
        with self._lock, self.conn:
            self.conn.execute(
                "INSERT INTO enrichment (key, data, created_at) VALUES (?, ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET data=excluded.data, created_at=excluded.created_at",
                (key, json.dumps(data), created_at),
            )

    # --- configuración -----------------------------------------------------
    def get_settings(self) -> dict:
        with self._lock:
            rows = self.conn.execute("SELECT key, value FROM settings").fetchall()
        settings = dict(DEFAULT_SETTINGS)
        settings.update({k: json.loads(v) for k, v in rows})
        return settings

    def update_settings(self, values: dict) -> dict:
        with self._lock, self.conn:
            for key, value in values.items():
                if key in DEFAULT_SETTINGS:
                    self.conn.execute(
                        "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                        (key, json.dumps(value)),
                    )
        return self.get_settings()
