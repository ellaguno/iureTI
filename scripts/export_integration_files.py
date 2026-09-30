"""Genera los archivos de integración para iurefficient con el código de la sonda.

  docs/integracion/identity_cases.json   casos de paridad (mismo formato que
                                         scripts/_inventory_identity_cases.json de iurefficient)
  docs/integracion/ejemplo-lote.json      POST /discovery/batches (activos de ejemplo, datos ficticios)
  docs/integracion/ejemplo-heartbeat.json POST /discovery/heartbeat (petición de ejemplo)

Uso: uv run python scripts/export_integration_files.py
Si cambia una regla de identidad o el catálogo de tipos, regenerar y avisar a iurefficient.
"""

import asyncio
import json
import tempfile
from datetime import date
from pathlib import Path

from iureti_discovery import __version__
from iureti_discovery.agent import Agent
from iureti_discovery.models import DEVICE_TYPES, Asset, Observation, SnmpInfo
from iureti_discovery.netutil import is_locally_administered, normalize_mac
from iureti_discovery.reconcile import Reconciler, identity_keys, normalize_hostname, normalize_serial
from iureti_discovery.runtime import Runtime
from iureti_discovery.store import Store
from iureti_discovery.sync import build_batch

OUT = Path(__file__).resolve().parent.parent / "docs" / "integracion"

SERIALS = ["To be filled by O.E.M.", "000000", " fcw2233l0ab ", "N/A", "xxx", "System Serial Number", "5CD1234XYZ",
           "", None, "-----", "0123456789", "abc 123", "Default string", "485754436371E3B5"]
MACS = ["00-1A-2B-3C-4D-5E", "bad", "da:a1:19:00:00:01", "001A.2B3C.4D5E", "AA:BB:CC:DD:EE:FF", "02:00:00:00:00:01",
        "", None, "00:1a:2b:3c:4d:5e:ff", "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "96:9e:f1:11:4d:33"]
HOSTNAMES = ["PC-ANA.corp.local", "192.168.1.10", "SW-CORE-01.", "", "  Laptop01  ", None, "10.0.0.1.",
             "_gateway", "_outbound", "Android_9XP64ZT9", "srv-contabilidad.corp.local"]
KEYS = [
    ["5CD1234XYZ", ["00:1a:2b:3c:4d:5e", "da:a1:19:00:00:01"], "pc-ana.corp"],
    ["n/a", [], "PC-X"],
    ["", ["bad"], ""],
    ["SN1", ["AA-BB-CC-DD-EE-FF"], "192.168.0.2"],
    ["", ["00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"], "_gateway"],
    ["", ["00:00:00:00:00:00", "00-1A-2B-3C-4D-5E"], "PC-B"],
    ["", ["96:9e:f1:11:4d:33"], "Android_9XP64ZT9"],
    ["485754436371E3B5", ["b0:a4:f0:4a:1b:ae"], ""],
]


def identity_cases() -> dict:
    return {
        "_origen": (f"Generado con las funciones de iureTI {__version__} (reconcile.py / netutil.py / models.py) "
                    f"el {date.today().isoformat()} por scripts/export_integration_files.py. "
                    "Contrato de paridad: el inventario debe dar lo mismo."),
        "device_types": DEVICE_TYPES,
        "serial": [[s, normalize_serial(s or "")] for s in SERIALS],
        "mac": [[m, normalize_mac(m or ""), is_locally_administered(m or "")] for m in MACS],
        "hostname": [[h, normalize_hostname(h or "")] for h in HOSTNAMES],
        "keys": [[args, identity_keys(*args)] for args in KEYS],
    }


def example_assets() -> list[Asset]:
    """Equipos ficticios con la forma de los reales (módem ONT, Pixel, switch con SNMP, impresora)."""
    ts = "2026-09-30T16:34:59Z"
    modem_upnp = {"deviceType": "urn:schemas-upnp-org:device:InternetGatewayDevice:1", "manufacturer": "Huawei",
                  "modelName": "Huawei EchoLife Series", "modelNumber": "Huawei Device",
                  "serialNumber": "485754436371E3B5", "serialDecoded": "HWTC6371E3B5"}
    observations = [
        Observation(ip="192.168.1.1", mac="b0:a4:f0:00:00:01", vendor="HUAWEI TECHNOLOGIES CO.,LTD",
                    open_ports=[23, 53, 80], alive_by=["ping", "tcp", "arp"], is_gateway=True, ttl=64,
                    upnp=modem_upnp, http={"model_candidates": ["HG8145X6"], "url": "http://192.168.1.1:80/",
                                           "status": 200}, observed_at=ts),
        Observation(ip="192.168.1.4", mac="96:9e:f1:00:00:02", alive_by=["ping", "arp", "mdns"], ttl=64,
                    mdns={"host": "Android_9XP64ZT9", "services": ["_kdeconnect._udp", "_fc9f5ed42c8a._tcp"],
                          "names": [], "txt": {"_kdeconnect._udp:name": "Pixel 9 Pro",
                                               "_kdeconnect._udp:type": "phone"}}, observed_at=ts),
        Observation(ip="10.0.0.2", mac="00:1a:2b:00:00:03", vendor="Cisco Systems, Inc", open_ports=[22, 443],
                    alive_by=["ping", "tcp"], ttl=255, observed_at=ts,
                    snmp=SnmpInfo(sys_descr="Cisco IOS XE Software, Version 17.09.04a, Catalyst L3 Switch Software (CAT9K_IOSXE)",
                                  sys_object_id="1.3.6.1.4.1.9.1.2494", sys_name="sw-core-01.corp.local",
                                  sys_location="Site: Matriz, Rack 2", serial="FCW2233L0AB", model="C9300-48P",
                                  credential="core-ro")),
        Observation(ip="10.0.0.50", mac="30:05:5c:00:00:04", vendor="Brother Industries, LTD.",
                    open_ports=[80, 443, 515, 631, 9100], alive_by=["ping", "tcp"], ttl=64, observed_at=ts,
                    hostname="prn-recepcion.corp.local",
                    mdns={"host": "BRN30055C000004", "services": ["_ipp._tcp", "_pdl-datastream._tcp"],
                          "names": [], "txt": {"_ipp._tcp:ty": "Brother MFC-L2710DW series"}}),
    ]
    rec = Reconciler([])
    assets = [rec.merge(o)[0] for o in observations]
    for a in assets:
        a.first_seen = ts
    # El módem ya identificado en internet (atributo product)
    assets[0].attributes["enrichment"] = {
        "identified": True, "manufacturer": "Huawei", "product_name": "Huawei EchoLife HG8145X6",
        "model": "HG8145X6", "device_type": "router",
        "description": "ONT GPON con Wi-Fi 6 (AX3000) para servicio de fibra óptica del proveedor.",
        "specs": ["GPON", "Wi-Fi 6 AX3000", "4 puertos GE", "1 puerto POTS", "USB"],
        "release_year": "2021", "support_status": "vigente",
        "product_url": "https://e.huawei.com/example/hg8145x6", "image_url": "https://e.huawei.com/example/hg8145x6.png",
        "confidence": "alta", "fetched_at": ts,
    }
    return assets


def example_batch() -> dict:
    batch = build_batch(example_assets(), {"probe_id": "sonda-matriz-01", "site": "Matriz CDMX"},
                        {"started_at": "2026-09-30T16:34:40Z", "finished_at": "2026-09-30T16:34:59Z",
                         "targets": ["192.168.1.0/24", "10.0.0.0/24"]})
    batch["batch_id"] = "0d6c3b1e-8f0a-4a57-9b7e-2a0c9c1e4f11"
    return batch


def example_heartbeat() -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        store = Store(Path(tmp) / "t.db")
        store.update_settings({"probe_id": "sonda-matriz-01", "site": "Matriz CDMX"})
        store.save_assets(example_assets())
        store.log_scan({"started_at": "2026-09-30T07:00:02Z", "finished_at": "2026-09-30T07:04:12Z",
                        "targets": ["192.168.1.0/24", "10.0.0.0/24"], "phase": "terminado", "alive": 4,
                        "error": ""}, 1)
        rt = Runtime(store)
        rt.last_sync = {"at": "2026-09-30T07:04:20Z", "sent": 4, "error": ""}
        agent = Agent(rt)
        agent.ack("cmd-17", "done", "4 hosts vivos, 1 nuevos")
        payload = asyncio.run(asyncio.to_thread(agent.payload))
    # Datos del equipo de ejemplo (no los de quien genera el archivo)
    payload["probe"].update(hostname="srv-inventario", os="Ubuntu 24.04.5 LTS", arch="x86_64", install="deb")
    payload["networks"] = [{"interface": "eth0", "network": "192.168.1.0/24"},
                           {"interface": "eth1", "network": "10.0.0.0/24"}]
    payload["config_version"] = "c-2026-09-30-3"
    return payload


def write(name: str, data) -> None:
    path = OUT / name
    path.write_text(json.dumps(data, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(f"escrito {path.relative_to(OUT.parent.parent)}")


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    write("identity_cases.json", identity_cases())
    write("ejemplo-lote.json", example_batch())
    write("ejemplo-heartbeat.json", example_heartbeat())
