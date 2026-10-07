"""Exportación y envío de activos a la API de inventario de iurefficient (ver docs/04-api-ingesta.md).

La sonda envía todo lo que ve; la aprobación ocurre en la bandeja de descubiertos de iurefficient.
"""

from __future__ import annotations

import csv
import io
import socket
import uuid

import httpx

from . import __version__, virtual
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
    "mobile": "Celular / tablet",
    "iot": "IoT",
    "unknown": "Equipo",
}


def asset_payload(asset: Asset, by_id: dict[str, Asset] | None = None) -> dict:
    """Un activo en el contrato de ingesta. `by_id` (todos los activos) resuelve el anfitrión de los virtuales."""
    snmp = asset.attributes.get("snmp") or {}
    attributes = {k: v for k, v in {
        "snmp_sys_object_id": snmp.get("sys_object_id", ""),
        "snmp_sys_descr": snmp.get("sys_descr", ""),
        "snmp_sys_contact": snmp.get("sys_contact", ""),
        "classification_reasons": asset.reasons,
        "announced_name": asset.attributes.get("announced_name", ""),
        "os_family": asset.attributes.get("os_family", ""),
        "upnp_serial_decoded": (asset.attributes.get("upnp") or {}).get("serialDecoded", ""),
        "product": product_summary(asset),
        "virtualization": virtual_summary(asset, by_id or {}),
        "guests": [{"probe_asset_id": g["id"], "name": g.get("name", ""), "ip": g.get("ip", ""), "kind": g.get("kind", ""),
                    "platform": g.get("platform", "")} for g in asset.attributes.get("guests") or []],
        "hosts_virtual": hosting_summary(asset),
        "superseded_probe_asset_ids": [m["id"] for m in asset.attributes.get("merged_from") or []],
        "mac_from": asset.attributes.get("mac_from", ""),
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


def virtual_summary(asset: Asset, by_id: dict[str, Asset]) -> dict:
    """Contenedor o VM y el equipo que lo aloja, en el contrato de iurefficient 1.8.0
    (`attributes.virtualization`: kind, runtime, name, host{hostname, serial, macs, probe_asset_id}),
    más lo que la sonda 0.5 sabe del anfitrión: su UUID en iurefficient, IP, confianza y evidencia."""
    v = asset.attributes.get("virtual") or {}
    if not v.get("kind"):
        return {}
    host = by_id.get(v.get("host_id", ""))
    host_info = {
        "hostname": (host.hostname if host else "") or v.get("host_name", ""),
        "serial": host.serial if host else "",
        "macs": [m for m in (host.macs if host else []) if m],
        "probe_asset_id": v.get("host_id", ""),
        "inventory_id": host.inventory_id if host else "",
        "ip": v.get("host_ip", "") or (host.ips[0] if host and host.ips else ""),
        "confidence": v.get("confidence", ""),
    }
    out = {
        "kind": v["kind"], "runtime": v.get("platform") or "unknown", "name": v.get("name", ""),
        "label": virtual.label(v), "reach": v.get("reach", "network"), "evidence": v.get("evidence", ""),
        "host": {k: x for k, x in host_info.items() if x},
        "host_candidates": [c.get("name", "") for c in v.get("host_candidates") or []],
    }
    return {k: x for k, x in out.items() if x}


def hosting_summary(asset: Asset) -> dict:
    h = asset.attributes.get("hosting") or {}
    out = {"vm_interfaces": h.get("vm_interfaces") or [], "container_interfaces": h.get("container_interfaces") or [],
           "vm_count": len(h.get("vms") or []), "vm_platforms": h.get("vm_platforms") or []}
    return {k: x for k, x in out.items() if x}


def product_summary(asset: Asset) -> dict:
    """Identificación por internet (si la hubo), sin la huella enviada ni rutas locales."""
    e = asset.attributes.get("enrichment") or {}
    if not e.get("identified"):
        return {}
    keys = ("product_name", "manufacturer", "model", "description", "specs", "release_year", "support_status",
            "product_url", "image_url", "confidence", "fetched_at")
    return {k: e[k] for k in keys if e.get(k)}


def clean_vendor(vendor: str) -> str:
    return "" if vendor.startswith("(") else vendor  # «(MAC aleatoria/local)» no es un fabricante


def build_batch(assets: list[Asset], settings: dict, last_scan: dict | None = None,
                all_assets: dict[str, Asset] | None = None) -> dict:
    """`all_assets` (id → activo, todos) permite citar al anfitrión de una VM aunque vaya en otro lote."""
    scan = last_scan or {}
    all_assets = all_assets or {a.id: a for a in assets}
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
        "assets": [asset_payload(a, all_assets) for a in assets],
    }


def suggested_name(asset: Asset) -> str:
    if asset.hostname:
        return asset.hostname.split(".")[0]
    label = DEVICE_TYPE_LABELS.get(asset.device_type, "Equipo")
    detail = " ".join(x for x in (clean_vendor(asset.vendor).split(",")[0], asset.model) if x)
    ip = asset.ips[0] if asset.ips else ""
    return " ".join(x for x in (label, detail, f"({ip})" if ip else "") if x)


def technical_description(asset: Asset) -> str:
    parts = []
    if product := product_summary(asset):
        parts.append(" — ".join(x for x in (product.get("product_name"), product.get("description")) if x))
        if product.get("product_url"):
            parts.append(f"Ficha: {product['product_url']}")
    parts.append(f"Tipo de dispositivo: {DEVICE_TYPE_LABELS.get(asset.device_type, asset.device_type)}")
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
    if text := virtual_description(asset):
        parts.append(text)
    parts.append(f"Descubierto por iureTI Discovery; visto por última vez {asset.last_seen}")
    return " · ".join(parts)


def virtual_description(asset: Asset) -> str:
    """«Virtual: máquina virtual VMware alojada en esx-01 (10.0.0.5)» o «Aloja: 3 contenedores, 1 máquina virtual»."""
    v = asset.attributes.get("virtual") or {}
    if v.get("kind"):
        where = virtual.host_label(v)
        ip = f" ({v['host_ip']})" if v.get("host_ip") and v.get("host_ip") != where else ""
        text = f"Virtual: {virtual.label(v)}"
        if where:
            text += f" alojado en {where}{ip}" + (" (probable)" if v.get("confidence") == "media" else "")
        elif v.get("host_candidates"):
            text += " · posibles anfitriones: " + ", ".join(c.get("name", "") for c in v["host_candidates"])
        return text
    guests = asset.attributes.get("guests") or []
    if guests:
        counts = {}
        for g in guests:
            counts[g.get("kind", "")] = counts.get(g.get("kind", ""), 0) + 1
        words = {"container": ("contenedor", "contenedores"), "vm": ("máquina virtual", "máquinas virtuales")}
        return "Aloja: " + ", ".join(f"{n} {words.get(k, (k, k))[0 if n == 1 else 1]}" for k, n in counts.items())
    return ""


def csv_safe(value: str) -> str:
    """Neutraliza la inyección de fórmulas: un equipo llamado «=HYPERLINK(...)» no debe ejecutarse
    al abrir el CSV en Excel/Sheets. Se antepone un apóstrofo a los valores que empiezan por =, +, -, @."""
    text = "" if value is None else str(value)
    if text and text[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + text
    return text


def to_import_csv(assets: list[Asset]) -> bytes:
    """CSV compatible con Inventario › Importar (1.1.0).

    Solo se llenan columnas técnicas; las celdas vacías no pisan nada en el importador.
    Ubicación y Notas se dejan vacías a propósito: son datos capturados a mano en iurefficient.
    """
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=IMPORT_HEADERS)
    writer.writeheader()
    for a in assets:
        writer.writerow({k: csv_safe(v) for k, v in {
            "Nombre": suggested_name(a),
            "Tipo": "Hardware",
            "Marca": clean_vendor(a.vendor),
            "Modelo": a.model,
            "Serie": a.serial,
            "Descripción": technical_description(a),
        }.items()})
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
