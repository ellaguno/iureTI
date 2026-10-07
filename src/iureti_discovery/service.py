"""Operaciones de alto nivel compartidas por la CLI y la interfaz web."""

from __future__ import annotations

import os

from . import enrich, virtual
from .classify import classify
from .models import utcnow
from .oui import OuiDatabase
from .reconcile import Reconciler
from .scanner import Scanner, ScanOptions, ScanProgress
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
        use_mdns=bool(s["use_mdns"]),
        use_ssdp=bool(s["use_ssdp"]),
        use_http=bool(s["use_http"]),
        use_netbios=bool(s["use_netbios"]),
        include_guests=bool(s.get("include_hosted_guests", True)),
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
        # Invitado ↔ anfitrión con todos los activos ya conciliados (los anfitriones pueden ser de otro escaneo)
        assets = list(rec.assets.values())
        virtual.annotate(assets, virtual.local_hosting(), settings_probe_name(store))
        for a in assets:
            if not a.type_locked and (a.attributes.get("virtual") or a.attributes.get("guests") or a.id in touched):
                a.device_type, a.confidence, a.reasons = classify(a)
        # Duplicados fusionados desaparecen; también se guardan activos a los que se les quitó una IP reasignada
        if rec.removed:
            store.delete_assets(list(rec.removed))
        store.save_assets(assets)
        return {"observed": len(observations), "assets": len(touched), "new": new_count, "merged": len(rec.removed)}
    finally:
        store.log_scan(scanner.progress.to_dict(), new_count)


def settings_probe_name(store: Store) -> str:
    import socket

    return store.get_settings().get("probe_id") or socket.gethostname()


def consolidate(store: Store) -> int:
    """Fusiona los duplicados que ya hubiera en la base (p.ej. de reglas de identidad anteriores).
    Devuelve cuántos activos se absorbieron."""
    rec = Reconciler(store.list_assets())
    if rec.removed:
        store.delete_assets(list(rec.removed))
        store.save_assets(list(rec.assets.values()))
    return len(rec.removed)


def sync_all(store: Store, only_changed: bool = False) -> dict:
    """Envía los activos a iurefficient en lotes. La aprobación ocurre allá (bandeja de descubiertos)."""
    settings = store.get_settings()
    assets = store.list_assets()
    all_assets = {a.id: a for a in assets}
    if only_changed:
        assets = [a for a in assets if not a.synced_at or a.synced_at < a.last_seen or a.remote_status == "rejected"]
    scans = store.list_scans(1)
    summary: dict = {"sent": 0, "batches": [], "results": {}}
    for i in range(0, len(assets), BATCH_SIZE):
        chunk = assets[i : i + BATCH_SIZE]
        batch = build_batch(chunk, settings, scans[0] if scans else None, all_assets)
        response = send_batch(batch, settings["api_url"], settings["api_token"])
        changed = apply_results(chunk, response)
        store.save_assets(changed)
        summary["sent"] += len(chunk)
        summary["batches"].append(batch["batch_id"])
        for a in changed:
            summary["results"][a.remote_status] = summary["results"].get(a.remote_status, 0) + 1
    return summary


def enrich_asset(store: Store, asset_id: str, force: bool = False, client=None) -> dict:
    """Identifica el producto de un activo en internet. Usa la caché por huella de producto."""
    settings = store.get_settings()
    if not settings.get("enrich_enabled"):
        raise enrich.EnrichError("La búsqueda en internet está desactivada (Configuración › Búsqueda en internet)")
    asset = store.get_asset(asset_id)
    if asset is None:
        raise enrich.EnrichError("Activo no encontrado")
    facts = enrich.product_facts(asset)
    if not enrich.has_product_clues(facts):
        raise enrich.EnrichError("No hay datos del producto para buscar (solo fabricante de la MAC o nada)")
    key = enrich.facts_key(facts)
    result = None if force else store.get_enrichment(key)
    cached = result is not None
    if result is None:
        provider = settings.get("enrich_provider") or "openrouter"
        if provider == "anthropic":
            model = settings.get("anthropic_model") or enrich.DEFAULT_MODEL
            client = client or enrich.make_client(settings.get("anthropic_api_key", ""))
            result = enrich.identify(facts, client, model)
        else:
            model = settings.get("openrouter_model") or enrich.OPENROUTER_DEFAULT_MODEL
            api_key = settings.get("openrouter_api_key") or os.environ.get("OPENROUTER_API_KEY", "")
            result = enrich.identify_openrouter(facts, api_key, model, settings.get("openrouter_web_engine", "exa"),
                                                http=client)
        result["image_url"], result["image_file"] = enrich.resolve_image(result)
        result["key"], result["fetched_at"], result["facts_sent"] = key, utcnow(), facts
        result["provider"], result["model_requested"] = provider, model
        store.save_enrichment(key, result, result["fetched_at"])
    enrich.apply(asset, result)
    if not asset.type_locked:
        asset.device_type, asset.confidence, asset.reasons = classify(asset)
    store.save_assets([asset])
    return {"asset": asset.to_dict(), "cached": cached}


def enrich_candidates(store: Store, only_missing: bool = True) -> list[str]:
    ids = []
    for a in store.list_assets():
        if only_missing and a.attributes.get("enrichment"):
            continue
        if enrich.has_product_clues(enrich.product_facts(a)):
            ids.append(a.id)
    return ids
