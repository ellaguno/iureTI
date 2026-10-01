"""Fabricante por MAC usando el registro OUI (MA-L) del IEEE."""

from __future__ import annotations

import csv
import io
import os
import ssl
import time
import urllib.error
import urllib.request
from pathlib import Path

from .netutil import is_locally_administered, normalize_mac

IEEE_OUI_URL = "https://standards-oui.ieee.org/oui/oui.csv"


MAX_OUI_BYTES = 32 * 1024 * 1024


class OuiUpdateError(RuntimeError):
    """No se pudo descargar la base de fabricantes (red/servidor del IEEE)."""


def _download(url: str, timeout: float) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "iureti-discovery"})
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:  # noqa: S310 (URL fija, https)
        if resp.status != 200:
            raise urllib.error.URLError(f"HTTP {resp.status}")
        return resp.read(MAX_OUI_BYTES).decode("utf-8", errors="replace")


def cache_dir() -> Path:
    if os.environ.get("IURETI_CACHE_DIR"):  # el servicio usa /var/cache/iureti
        path = Path(os.environ["IURETI_CACHE_DIR"])
    else:
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

    def update(self, timeout: float = 60.0, retries: int = 3) -> int:
        # Se usa urllib (no httpx): el WAF del IEEE corta el ClientHello de httpx pero acepta el de
        # la biblioteca estándar. Aun así el servidor es inestable, así que se reintenta.
        last_exc: Exception | None = None
        for attempt in range(retries):
            try:
                text = _download(IEEE_OUI_URL, timeout)
                table = parse_oui_csv(text)
                if not table:
                    raise ValueError("El archivo OUI descargado no contiene registros")
                tmp = self.path.with_suffix(".tmp")
                tmp.write_text(text, encoding="utf-8")
                tmp.replace(self.path)
                self._table = table
                return len(table)
            except (urllib.error.URLError, OSError, ValueError) as exc:
                last_exc = exc
                if attempt < retries - 1:
                    time.sleep(2 * (attempt + 1))
        raise OuiUpdateError(
            "No se pudo descargar la base de fabricantes del IEEE "
            f"(standards-oui.ieee.org): {last_exc}. La sonda funciona sin ella (no mostrará el "
            "fabricante por MAC); reintenta más tarde con «iureti-discovery oui-update»."
        ) from last_exc

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
