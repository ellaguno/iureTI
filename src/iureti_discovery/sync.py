"""Exportación y envío de activos a la API de inventario de iurefficient (ver docs/04-api-ingesta.md).

La sonda envía todo lo que ve; la aprobación ocurre en la bandeja de descubiertos de iurefficient.
"""

from __future__ import annotations

import csv
import io
import socket
import uuid

import httpx

from . import __version__
from .models import Asset, utcnow

INGEST_PATH = "/api/plugins/inventory/discovery/batches"
BATCH_SIZE = 500

# Encabezados de la plantilla de importación del inventario 1.1.0 (iur_inventory/import_service.py),
# más «Descripción», que el importador también reconoce.
IMPORT_HEADERS = [
    "SKU", "Nombre", "Tipo", "Estado", "Categoría", "Ubicación", "Marca", "Modelo",
    "Serie", "Responsable", "Fecha de compra", "Precio de compra", "Moneda",
    "Garantía hasta", "Licencia vence", "Asientos", "Clave de licencia",
    "Cantidad", "Mínimo", "Notas", "Descripción",
]

DEVICE_TYPE_LABELS = {
    "workstation": "Equipo de escritorio",
    "laptop": "Laptop",
    "server": "Servidor",
    "switch": "Switch",
    "router": "Router",
    "firewall": "Firewall",
    "access_point": "Access point",
    "printer": "Impresora",
    "ups": "UPS",
    "nas": "NAS",
    "hypervisor": "Hipervisor",
    "camera": "Cámara",
    "phone": "Teléfono IP",
    "iot": "IoT",
    "unknown": "Equipo",
}


def asset_payload(asset: Asset) -> dict:
    snmp = asset.attributes.get("snmp") or {}
    attributes = {k: v for k, v in {
        "snmp_sys_object_id": snmp.get("sys_object_id", ""),
        "snmp_sys_descr": snmp.get("sys_descr", ""),
        "snmp_sys_contact": snmp.get("sys_contact", ""),
        "classification_reasons": asset.reasons,
    }.items() if v}
    return {
        "probe_asset_id": asset.id,
        "fingerprint": asset.fingerprint,
        "device_type": asset.device_type,
        "confidence": asset.confidence,
        "hostname": asset.hostname,
        "ips": asset.ips,
        "macs": asset.macs,
        "vendor": clean_vendor(asset.vendor),
        "model": asset.model,
        "serial": asset.serial,
        "os": asset.os,
        "open_ports": asset.open_ports,
        "location": asset.location,
        "sources": asset.sources,
        "first_seen": asset.first_seen,
        "last_seen": asset.last_seen,
        "attributes": attributes,
    }


def clean_vendor(vendor: str) -> str:
    return "" if vendor.startswith("(") else vendor  # «(MAC aleatoria/local)» no es un fabricante


def build_batch(assets: list[Asset], settings: dict, last_scan: dict | None = None) -> dict:
    scan = last_scan or {}
    return {
        "batch_id": str(uuid.uuid4()),
        "probe": {
            "id": settings.get("probe_id") or socket.gethostname(),
            "version": __version__,
            "site": settings.get("site", ""),
        },
        "scan": {
            "started_at": scan.get("started_at", ""),
            "finished_at": scan.get("finished_at", ""),
            "targets": scan.get("targets", []),
            "collectors": sorted({s for a in assets for s in a.sources}),
        },
        "assets": [asset_payload(a) for a in assets],
    }


def suggested_name(asset: Asset) -> str:
    if asset.hostname:
        return asset.hostname.split(".")[0]
    label = DEVICE_TYPE_LABELS.get(asset.device_type, "Equipo")
    detail = " ".join(x for x in (clean_vendor(asset.vendor).split(",")[0], asset.model) if x)
    ip = asset.ips[0] if asset.ips else ""
    return " ".join(x for x in (label, detail, f"({ip})" if ip else "") if x)


def technical_description(asset: Asset) -> str:
    parts = [f"Tipo de dispositivo: {DEVICE_TYPE_LABELS.get(asset.device_type, asset.device_type)}"]
    if asset.hostname:
        parts.append(f"Hostname: {asset.hostname}")
    if asset.ips:
        parts.append("IP: " + ", ".join(asset.ips))
    if asset.macs:
        parts.append("MAC: " + ", ".join(asset.macs))
    if asset.os:
        parts.append(f"SO/firmware: {asset.os}")
    if asset.location:
        parts.append(f"Ubicación SNMP: {asset.location}")
    parts.append(f"Descubierto por iureTI Discovery; visto por última vez {asset.last_seen}")
    return " · ".join(parts)


def to_import_csv(assets: list[Asset]) -> bytes:
    """CSV compatible con Inventario › Importar (1.1.0).

    Solo se llenan columnas técnicas; las celdas vacías no pisan nada en el importador.
    Ubicación y Notas se dejan vacías a propósito: son datos capturados a mano en iurefficient.
    """
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=IMPORT_HEADERS)
    writer.writeheader()
    for a in assets:
        writer.writerow({
            "Nombre": suggested_name(a),
            "Tipo": "Hardware",
            "Marca": clean_vendor(a.vendor),
            "Modelo": a.model,
            "Serie": a.serial,
            "Descripción": technical_description(a),
        })
    return buf.getvalue().encode("utf-8-sig")


class SyncError(RuntimeError):
    pass


def send_batch(batch: dict, api_url: str, token: str, timeout: float = 30.0) -> dict:
    if not api_url or not token:
        raise SyncError("Configura la URL de iurefficient y el token de la sonda")
    url = api_url.rstrip("/") + INGEST_PATH
    try:
        resp = httpx.post(url, json=batch, headers={"Authorization": f"Bearer {token}"}, timeout=timeout)
    except httpx.HTTPError as exc:
        raise SyncError(f"No se pudo conectar con {url}: {exc}") from exc
    if resp.status_code >= 400:
        raise SyncError(f"La API respondió {resp.status_code}: {resp.text[:300]}")
    return resp.json() if resp.content else {}


def apply_results(assets: list[Asset], response: dict) -> list[Asset]:
    """Guarda en cada activo lo que respondió iurefficient."""
    by_id = {a.id: a for a in assets}
    now = utcnow()
    results = response.get("results")
    if results is None:  # la API aceptó el lote sin detalle
        results = [{"probe_asset_id": a.id, "status": "accepted"} for a in assets]
    changed = []
    for r in results:
        asset = by_id.get(r.get("probe_asset_id"))
        if not asset:
            continue
        asset.remote_status = str(r.get("status") or "")
        asset.remote_reason = str(r.get("reason") or "")
        if asset.remote_status != "rejected":
            asset.synced_at = now
            asset.inventory_id = str(r.get("inventory_id") or asset.inventory_id)
        changed.append(asset)
    return changed
