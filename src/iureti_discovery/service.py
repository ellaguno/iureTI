"""Operaciones de alto nivel compartidas por la CLI y la interfaz web."""

from __future__ import annotations

from .oui import OuiDatabase
from .reconcile import Reconciler
from .scanner import ScanOptions, ScanProgress, Scanner
from .snmp import SnmpCredential
from .store import Store
from .sync import BATCH_SIZE, apply_results, build_batch, send_batch


def credentials_from_settings(settings: dict) -> list[SnmpCredential]:
    known = SnmpCredential.__dataclass_fields__
    return [SnmpCredential(**{k: v for k, v in c.items() if k in known}) for c in settings.get("snmp_credentials", [])]


def make_scanner(store: Store, targets: list[str], progress: ScanProgress | None = None,
                 oui: OuiDatabase | None = None, use_snmp: bool = True) -> Scanner:
    s = store.get_settings()
    opts = ScanOptions(
        targets=targets,
        snmp_credentials=credentials_from_settings(s) if use_snmp else [],
        concurrency=int(s["concurrency"]),
        tcp_timeout=float(s["tcp_timeout"]),
        use_ping=bool(s["use_ping"]),
        resolve_dns=bool(s["resolve_dns"]),
    )
    return Scanner(opts, oui=oui, progress=progress)


async def run_scan(store: Store, scanner: Scanner) -> dict:
    """Ejecuta el escaneo, concilia contra la BD y guarda. Devuelve un resumen."""
    new_count = 0
    try:
        observations = await scanner.run()
        rec = Reconciler(store.list_assets())
        touched = {}
        for obs in observations:
            asset, is_new = rec.merge(obs)
            new_count += is_new
            touched[asset.id] = asset
        # También se guardan activos a los que se les quitó una IP reasignada
        store.save_assets(list(rec.assets.values()))
        return {"observed": len(observations), "assets": len(touched), "new": new_count}
    finally:
        store.log_scan(scanner.progress.to_dict(), new_count)


def sync_all(store: Store, only_changed: bool = False) -> dict:
    """Envía los activos a iurefficient en lotes. La aprobación ocurre allá (bandeja de descubiertos)."""
    settings = store.get_settings()
    assets = store.list_assets()
    if only_changed:
        assets = [a for a in assets if not a.synced_at or a.synced_at < a.last_seen or a.remote_status == "rejected"]
    scans = store.list_scans(1)
    summary: dict = {"sent": 0, "batches": [], "results": {}}
    for i in range(0, len(assets), BATCH_SIZE):
        chunk = assets[i : i + BATCH_SIZE]
        batch = build_batch(chunk, settings, scans[0] if scans else None)
        response = send_batch(batch, settings["api_url"], settings["api_token"])
        changed = apply_results(chunk, response)
        store.save_assets(changed)
        summary["sent"] += len(chunk)
        summary["batches"].append(batch["batch_id"])
        for a in changed:
            summary["results"][a.remote_status] = summary["results"].get(a.remote_status, 0) + 1
    return summary
