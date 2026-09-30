"""Fabricante por MAC usando el registro OUI (MA-L) del IEEE."""

from __future__ import annotations

import csv
import io
import os
from pathlib import Path

import httpx

from .netutil import is_locally_administered, normalize_mac

IEEE_OUI_URL = "https://standards-oui.ieee.org/oui/oui.csv"


def cache_dir() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache")
    path = Path(base) / "iureti-discovery"
    path.mkdir(parents=True, exist_ok=True)
    return path


def parse_oui_csv(text: str) -> dict[str, str]:
    """Columnas IEEE: Registry, Assignment, Organization Name, Organization Address."""
    table = {}
    for row in csv.DictReader(io.StringIO(text)):
        prefix = (row.get("Assignment") or "").strip().upper()
        org = (row.get("Organization Name") or "").strip()
        if len(prefix) == 6 and org:
            table[prefix] = org
    return table


class OuiDatabase:
    def __init__(self, path: Path | None = None):
        self.path = path or cache_dir() / "oui.csv"
        self._table: dict[str, str] | None = None

    @property
    def available(self) -> bool:
        return self.path.exists()

    def update(self, timeout: float = 60.0) -> int:
        resp = httpx.get(IEEE_OUI_URL, timeout=timeout, follow_redirects=True, headers={"User-Agent": "iureti-discovery"})
        resp.raise_for_status()
        table = parse_oui_csv(resp.text)
        if not table:
            raise RuntimeError("El archivo OUI descargado no contiene registros")
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(resp.text, encoding="utf-8")
        tmp.replace(self.path)
        self._table = table
        return len(table)

    def _load(self) -> dict[str, str]:
        if self._table is None:
            self._table = parse_oui_csv(self.path.read_text(encoding="utf-8")) if self.available else {}
        return self._table

    def lookup(self, mac: str) -> str:
        mac = normalize_mac(mac)
        if not mac:
            return ""
        if is_locally_administered(mac):
            return "(MAC aleatoria/local)"
        return self._load().get(mac.replace(":", "")[:6].upper(), "")
