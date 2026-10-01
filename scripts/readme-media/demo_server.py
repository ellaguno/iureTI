"""Servidor de demostración para las capturas del README.

Arranca la interfaz web REAL de iureTI Discovery (create_app) sobre una base de datos y una caché
TEMPORALES, con datos 100 % ficticios. No escanea ninguna red ni envía nada a ningún lado:

- netutil.local_networks devuelve dos redes ficticias (no las de este equipo);
- Runtime.start_scan se sustituye por un escaneo simulado que recorre las fases reales
  (barrido, anuncios UPnP, puertos, enriquecimiento) y al terminar guarda los activos ficticios;
- service.sync_all se sustituye por un envío simulado (no hay red).

La clasificación (tipo, confianza y motivos) la calcula el clasificador real (classify.classify).

Uso:  uv run python scripts/readme-media/demo_server.py --data /tmp/iureti-demo --port 8766
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--data", required=True, help="Directorio temporal (se crea)")
parser.add_argument("--port", type=int, default=8766)
args = parser.parse_args()

DATA = Path(args.data)
(DATA / "cache" / "images").mkdir(parents=True, exist_ok=True)
os.environ["IURETI_DB"] = str(DATA / "iureti.db")
os.environ["IURETI_CACHE_DIR"] = str(DATA / "cache")
(DATA / "cache" / "oui.csv").write_text("Registry,Assignment,Organization Name,Organization Address\n")

import uvicorn  # noqa: E402

from iureti_discovery import netutil, service  # noqa: E402
from iureti_discovery.classify import classify  # noqa: E402
from iureti_discovery.models import Asset  # noqa: E402
from iureti_discovery.runtime import Busy, Runtime  # noqa: E402
from iureti_discovery.store import Store  # noqa: E402
from iureti_discovery.web.app import create_app  # noqa: E402

NOW = datetime.now(timezone.utc).replace(microsecond=0)


def iso(dt: datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z")


# --------------------------------------------------------------------------- redes ficticias
netutil.local_networks = lambda: [
    netutil.LocalNetwork(interface="eth0", address="192.168.50.14", network="192.168.50.0/24", virtual=False),
    netutil.LocalNetwork(interface="eth1", address="10.20.0.14", network="10.20.0.0/24", virtual=False),
]

# --------------------------------------------------------------------------- activos ficticios
WIN_WS = [135, 139, 445, 3389]
WIN_SRV = [80, 135, 139, 443, 445, 3389, 5985]


def snmp(descr, oid, name, cred="gestion-v3", location="", serial="", model=""):
    return {"sys_descr": descr, "sys_object_id": oid, "sys_name": name, "sys_location": location,
            "sys_contact": "soporte@demo.iurefficient.com" if location else "", "serial": serial,
            "model": model, "credential": cred}


ENRICH_FETCHED = iso(NOW - timedelta(minutes=3))

ENRICH = {
    "fw-matriz": {
        "manufacturer": "Fortinet", "product_name": "FortiGate 60F", "model": "FG-60F", "device_type": "firewall",
        "description": "Firewall de nueva generación para sucursales y oficinas medianas, con SD-WAN integrado.",
        "specs": ["10 puertos GE RJ45", "Throughput de firewall: 10 Gbps", "Throughput IPS: 1.4 Gbps",
                  "Procesador de seguridad SoC4"],
        "release_year": "2019", "support_status": "vigente", "product_url": "https://www.fortinet.com/products/next-generation-firewall",
        "confidence": "alta", "img": "firewall", "cost": 0.0124,
    },
    "sw-core-01": {
        "manufacturer": "Cisco", "product_name": "Catalyst 9200L-24P-4G", "model": "C9200L-24P-4G", "device_type": "switch",
        "description": "Switch de acceso apilable de 24 puertos Gigabit con PoE+ y 4 enlaces de subida de 1G.",
        "specs": ["24 puertos 10/100/1000 PoE+", "Presupuesto PoE: 370 W", "4 × 1G SFP de subida", "Cisco IOS XE"],
        "release_year": "2019", "support_status": "vigente", "product_url": "https://www.cisco.com/c/en/us/products/switches/catalyst-9200-series-switches/index.html",
        "confidence": "alta", "img": "switch", "cost": 0.0098,
    },
    "nas-respaldos": {
        "manufacturer": "Synology", "product_name": "DiskStation DS920+", "model": "DS920+", "device_type": "nas",
        "description": "NAS de 4 bahías para respaldos y archivos compartidos, ampliable con unidad de expansión.",
        "specs": ["4 bahías 3.5\"/2.5\"", "Intel Celeron J4125", "4 GB DDR4 (hasta 8 GB)", "2 × 1GbE", "2 ranuras M.2 NVMe"],
        "release_year": "2020", "support_status": "vigente", "product_url": "https://www.synology.com/products/DS920+",
        "confidence": "alta", "img": "nas", "cost": 0.0087,
    },
    "prn-contabilidad": {
        "manufacturer": "Brother", "product_name": "Brother HL-L6210DW", "model": "HL-L6210DW", "device_type": "printer",
        "description": "Impresora láser monocromática para oficina con dúplex automático y red inalámbrica.",
        "specs": ["Hasta 52 ppm", "Dúplex automático", "Ethernet, Wi-Fi y USB", "Bandeja de 520 hojas"],
        "release_year": "2023", "support_status": "vigente", "product_url": "https://www.brother-usa.com/products/hll6210dw",
        "confidence": "alta", "img": "printer", "cost": 0.0112,
    },
    "ap-sala-juntas": {
        "manufacturer": "Ubiquiti", "product_name": "UniFi U6 Pro", "model": "U6-Pro", "device_type": "access_point",
        "description": "Access point Wi-Fi 6 de techo para espacios de alta densidad, alimentado por PoE.",
        "specs": ["Wi-Fi 6 doble banda 4×4", "Hasta 5.3 Gbps agregados", "Más de 300 clientes", "PoE 802.3at"],
        "release_year": "2021", "support_status": "vigente", "product_url": "https://store.ui.com/us/en/products/u6-pro",
        "confidence": "alta", "img": "ap", "cost": 0.0079,
    },
    "ups-rack": {
        "manufacturer": "APC", "product_name": "Smart-UPS 1500 VA LCD RM 2U", "model": "SMT1500RM2U", "device_type": "ups",
        "description": "UPS interactivo de montaje en rack 2U con pantalla LCD y tarjeta de red para monitoreo.",
        "specs": ["1500 VA / 1000 W", "Onda senoidal pura", "6 salidas NEMA 5-15R", "Tarjeta de red NMC"],
        "release_year": "2014", "support_status": "vigente", "product_url": "https://www.apc.com/",
        "confidence": "media", "img": "ups", "cost": 0.0101,
    },
}

# (ip, hostname, mac, vendor, model, serial, os, ports, attributes, días desde la primera vez)
DEVICES = [
    ("10.20.0.1", "fw-matriz", "00:09:0f:a4:21:7c", "Fortinet, Inc.", "FortiGate-60F", "FGT60FTK21000123", "",
     [22, 443], {"snmp": snmp("FortiGate-60F v7.4.4,build2662", ".1.3.6.1.4.1.12356.101.1.641", "fw-matriz",
                              location="Site de cómputo, rack 1", serial="FGT60FTK21000123", model="FortiGate-60F"),
                 "is_gateway": True, "ttl": 255, "os_family": "network"}, 40),
    ("10.20.0.2", "sw-core-01", "00:1b:54:3e:90:c1", "Cisco Systems, Inc", "C9200L-24P-4G", "JAE24410ABC", "",
     [22, 80, 443], {"snmp": snmp("Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_LITE_IOSXE), Version 17.9.4",
                                  ".1.3.6.1.4.1.9.1.2687", "sw-core-01", location="Site de cómputo, rack 1",
                                  serial="JAE24410ABC", model="C9200L-24P-4G"), "ttl": 255, "os_family": "network"}, 40),
    ("10.20.0.10", "srv-archivos", "f8:bc:12:6d:04:aa", "Dell Inc.", "", "", "",
     WIN_SRV, {"netbios": {"name": "SRV-ARCHIVOS", "group": "RUIZASOC"}, "ttl": 128, "os_family": "windows"}, 40),
    ("10.20.0.11", "dc01", "f8:bc:12:6d:11:3e", "Dell Inc.", "", "", "",
     [53, 88, 135, 139, 389, 445, 636, 3268, 3389], {"netbios": {"name": "DC01", "group": "RUIZASOC"}, "ttl": 128,
                                                      "os_family": "windows"}, 40),
    ("10.20.0.20", "pve-01", "00:25:90:b2:7f:18", "Super Micro Computer, Inc.", "", "", "",
     [22, 111, 8006], {"http": {"title": "pve-01 - Proxmox Virtual Environment", "server": "pve-api-daemon/3.0",
                                "url": "https://10.20.0.20:8006/"}, "ttl": 64, "os_family": "unix"}, 32),
    ("10.20.0.30", "nas-respaldos", "00:11:32:9c:5a:e2", "Synology Incorporated", "DS920+", "", "",
     [22, 139, 445, 5000, 5001], {"snmp": snmp("Linux nas-respaldos 4.4.302+ #69057 SMP x86_64", ".1.3.6.1.4.1.6574.1",
                                              "nas-respaldos", cred="gestion-v3", model="DS920+"),
                                 "mdns": {"host": "nas-respaldos.local", "services": ["_smb._tcp", "_http._tcp", "_afpovertcp._tcp"],
                                          "names": ["nas-respaldos"], "txt": {"model": "DS920+"}},
                                 "ttl": 64, "os_family": "unix"}, 40),
    ("10.20.0.40", "ups-rack", "00:c0:b7:5e:31:0d", "American Power Conversion Corp", "Smart-UPS 1500", "", "",
     [80, 443], {"snmp": snmp("APC Web/SNMP Management Card (MB:v4.1.0 PF:v6.9.6 AOS:v6.9.6 APP:v6.9.6)",
                              ".1.3.6.1.4.1.318.1.3.27", "ups-rack", location="Site de cómputo, rack 1",
                              model="Smart-UPS 1500"), "ttl": 64, "os_family": "unix"}, 40),
    ("192.168.50.2", "sw-piso1", "fc:ec:da:41:8b:20", "Ubiquiti Inc", "USW-Pro-24-PoE", "", "",
     [22, 80, 443], {"snmp": snmp("USW-Pro-24-PoE, 7.0.50.15613, Linux 3.6.5", ".1.3.6.1.4.1.4413", "sw-piso1",
                                  cred="oficina-v2c", model="USW-Pro-24-PoE"), "ttl": 64, "os_family": "unix"}, 25),
    ("192.168.50.5", "ap-recepcion", "fc:ec:da:73:1c:4e", "Ubiquiti Inc", "U6-Lite", "", "",
     [22], {"upnp": {"deviceType": "urn:schemas-upnp-org:device:WLANAccessPointDevice:1", "manufacturer": "Ubiquiti Networks",
                     "modelName": "U6-Lite"}, "ttl": 64, "os_family": "unix"}, 25),
    ("192.168.50.6", "ap-sala-juntas", "fc:ec:da:73:2a:91", "Ubiquiti Inc", "U6-Pro", "", "",
     [22], {"upnp": {"deviceType": "urn:schemas-upnp-org:device:WLANAccessPointDevice:1", "manufacturer": "Ubiquiti Networks",
                     "modelName": "U6-Pro"}, "ttl": 64, "os_family": "unix"}, 25),
    ("192.168.50.20", "prn-contabilidad", "00:80:77:d1:42:6b", "Brother industries, LTD.", "HL-L6210DW", "U64012K3N123456", "",
     [80, 443, 515, 631, 9100], {"snmp": snmp("Brother NC-8800w, Firmware Ver.1.04 (23.06.01)", ".1.3.6.1.4.1.2435.2.3.9.1",
                                             "prn-contabilidad", cred="oficina-v2c", location="Contabilidad, piso 1",
                                             serial="U64012K3N123456", model="HL-L6210DW"),
                                 "mdns": {"host": "prn-contabilidad.local", "services": ["_ipp._tcp", "_printer._tcp"],
                                          "names": ["Brother HL-L6210DW series"], "txt": {"ty": "Brother HL-L6210DW series"}},
                                 "ttl": 64}, 25),
    ("192.168.50.21", "prn-direccion", "3c:52:82:a8:0e:17", "Hewlett Packard", "LaserJet Pro M404dn", "", "",
     [80, 443, 631, 9100], {"http": {"title": "HP LaserJet Pro M404dn", "server": "HP HTTP Server; HP LaserJet Pro M404-M405",
                                     "model_candidates": ["M404dn"], "url": "https://192.168.50.21/"}, "ttl": 255}, 25),
    ("192.168.50.22", "prn-recepcion", "64:eb:8c:39:7a:c4", "Seiko Epson Corporation", "WF-C5790", "", "",
     [80, 443, 515, 631, 9100], {"mdns": {"host": "EPSON397AC4.local", "services": ["_ipp._tcp", "_scanner._tcp"],
                                          "names": ["EPSON WF-C5790 Series"], "txt": {"ty": "EPSON WF-C5790 Series"}},
                                 "ttl": 64}, 18),
    ("192.168.50.101", "pc-recepcion", "b8:ca:3a:5f:22:91", "Dell Inc.", "", "", "",
     WIN_WS, {"netbios": {"name": "PC-RECEPCION", "group": "RUIZASOC"}, "ttl": 128, "os_family": "windows"}, 25),
    ("192.168.50.102", "pc-contab-01", "3c:52:82:61:9d:04", "Hewlett Packard", "", "", "",
     WIN_WS, {"netbios": {"name": "PC-CONTAB-01", "group": "RUIZASOC"}, "ttl": 128, "os_family": "windows"}, 25),
    ("192.168.50.103", "pc-contab-02", "3c:52:82:61:9e:7a", "Hewlett Packard", "", "", "",
     WIN_WS, {"netbios": {"name": "PC-CONTAB-02", "group": "RUIZASOC"}, "ttl": 128, "os_family": "windows"}, 25),
    ("192.168.50.104", "pc-direccion", "b8:ca:3a:5f:41:c8", "Dell Inc.", "", "", "",
     WIN_WS, {"netbios": {"name": "PC-DIRECCION", "group": "RUIZASOC"}, "ttl": 128, "os_family": "windows"}, 25),
    ("192.168.50.121", "lap-mlopez", "54:e1:ad:3d:7a:19", "LCFC(HeFei) Electronics Technology co., ltd", "", "", "",
     WIN_WS, {"netbios": {"name": "LAP-MLOPEZ", "group": "RUIZASOC"}, "ttl": 128, "os_family": "windows"}, 9),
    ("192.168.50.120", "lap-atorres", "f0:18:98:6c:02:d5", "Apple, Inc.", "MacBook Pro", "", "",
     [22, 5900], {"mdns": {"host": "lap-atorres.local", "services": ["_ssh._tcp", "_rfb._tcp", "_companion-link._tcp"],
                           "names": ["lap-atorres"], "txt": {"model": "MacBookPro18,3", "type": "laptop"}},
                  "ttl": 64, "os_family": "unix"}, 12),
    ("192.168.50.122", "nb-druiz", "f0:18:98:4b:7e:21", "Apple, Inc.", "MacBook Air", "", "",
     [22, 5900], {"mdns": {"host": "nb-druiz.local", "services": ["_ssh._tcp", "_rfb._tcp", "_companion-link._tcp"],
                           "names": ["nb-druiz"], "txt": {"model": "MacBookAir10,1", "type": "laptop"}},
                  "ttl": 64, "os_family": "unix"}, 6),
    ("192.168.50.140", "tel-recepcion", "80:5e:c0:17:3b:a2", "YEALINK(XIAMEN) NETWORK TECHNOLOGY CO.,LTD.", "SIP-T54W", "", "",
     [80, 443, 5060], {"http": {"title": "Yealink SIP-T54W", "server": "", "model_candidates": ["SIP-T54W"],
                                "url": "https://192.168.50.140/"}, "ttl": 64}, 25),
]


def fingerprint(serial: str, mac: str) -> str:
    return f"serial:{serial.upper()}" if serial else f"mac:{mac}"


def build_assets() -> list[Asset]:
    assets = []
    for ip, host, mac, vendor, model, serial, os_, ports, attrs, days in DEVICES:
        a = Asset(hostname=host, ips=[ip], macs=[mac], vendor=vendor, model=model, serial=serial, os=os_,
                  open_ports=sorted(ports), first_seen=iso(NOW - timedelta(days=days, hours=3)), last_seen=iso(NOW))
        a.attributes = {"alive_by": ["ping", "tcp", "arp"] if ports else ["ping", "arp"], **attrs}
        # Como lo deja reconcile.py: SO = 1.ª línea del sysDescr, o «Windows (por TTL)»
        if not a.os and "snmp" in attrs:
            a.os = attrs["snmp"]["sys_descr"].splitlines()[0][:200]
        elif not a.os and attrs.get("os_family") == "windows":
            a.os = "Windows (por TTL)"
        a.fingerprint = fingerprint(serial, mac)
        if host in ENRICH:
            e = dict(ENRICH[host])
            img, cost = e.pop("img"), e.pop("cost")
            e.update(identified=True, notes="", fetched_at=ENRICH_FETCHED, provider="openrouter",
                     model_requested="google/gemini-3.1-flash-lite", model_used="google/gemini-3.1-flash-lite",
                     cost_usd=cost, image_file=f"{img_id(img)}.png", image_url="")
            a.attributes["enrichment"] = e
        src = ["sweep", "ports", "oui"] + [s for s in ("snmp", "mdns", "upnp", "http", "netbios") if s in a.attributes]
        a.sources = src
        a.location = a.attributes.get("snmp", {}).get("sys_location", "")
        a.device_type, a.confidence, a.reasons = classify(a)
        assets.append(a)
    return assets


def img_id(name: str) -> str:
    # Nombre de archivo de imagen aceptado por la API: 20 hex
    return (name.encode().hex() + "0" * 20)[:20]


ASSETS = build_assets()

# --------------------------------------------------------------------------- base temporal
store = Store()
store.update_settings({
    "probe_id": "sonda-matriz", "site": "Matriz", "targets": ["192.168.50.0/24", "10.20.0.0/24"],
    "api_url": "https://demo.iurefficient.com", "api_token": "iurprobe_demo_no_es_real",
    "snmp_credentials": [
        {"name": "gestion-v3", "version": "3", "user": "inventario", "auth_protocol": "SHA256", "auth_key": "demo-auth",
         "priv_protocol": "AES", "priv_key": "demo-priv", "networks": ["10.20.0.0/24"]},
        {"name": "oficina-v2c", "version": "2c", "community": "demo-ro", "networks": ["192.168.50.0/26"]},
    ],
    "enrich_enabled": True, "openrouter_api_key": "", "schedule_interval_minutes": 360,
    "schedule_window": "01:00-05:00", "auto_sync": True, "auto_enrich": True,
})
store.conn.execute(
    "INSERT INTO scans (started_at, finished_at, targets, phase, alive, new_assets, error) VALUES (?,?,?,?,?,?,?)",
    (iso(NOW - timedelta(days=1, hours=2)), iso(NOW - timedelta(days=1, hours=2) + timedelta(seconds=74)),
     '["10.20.0.0/24"]', "terminado", 7, 7, None))
store.conn.commit()
# Los activos de la red de servidores ya se conocían de ayer (el escaneo de hoy agrega la oficina)
store.save_assets([a for a in ASSETS if a.ips[0].startswith("10.20.")])

# --------------------------------------------------------------------------- escaneo simulado
DEMO_SPEED = float(os.environ.get("DEMO_SPEED", "1"))


def fake_start_scan(self: Runtime, targets, use_snmp=True, remember=True):
    if self.progress.running:
        raise Busy("Ya hay un escaneo en curso")
    if not targets:
        raise ValueError("Indica al menos un rango")
    ips = netutil.expand_targets(targets)
    if remember:
        self.store.update_settings({"targets": targets})
    p = self.progress
    p.targets, p.error, p.cancelled = list(targets), "", False
    p.started_at, p.finished_at, p.phase, p.alive = iso(datetime.now(timezone.utc).replace(microsecond=0)), "", "iniciando", 0
    alive_total = len(ASSETS)

    async def job():
        sleep = lambda s: asyncio.sleep(s / DEMO_SPEED)  # noqa: E731
        await sleep(0.4)
        p.phase, p.total, p.done = "barrido", len(ips), 0
        steps = 24
        for i in range(1, steps + 1):
            p.done = round(len(ips) * i / steps)
            p.alive = round(alive_total * i / steps)
            await sleep(0.18)
        p.phase, p.total, p.done = "anuncios UPnP", 1, 0
        await sleep(0.8)
        p.done = 1
        p.phase, p.total, p.done = "puertos", alive_total, 0
        for i in range(1, alive_total + 1):
            p.done = i
            await sleep(0.07)
        p.phase, p.total, p.done = "enriquecimiento", alive_total, 0
        for i in range(1, alive_total + 1):
            p.done = i
            await sleep(0.06)
        known = {a.id for a in self.store.list_assets()}
        new = [a for a in ASSETS if a.id not in known]
        self.store.save_assets(ASSETS)
        p.phase, p.finished_at = "terminado", iso(datetime.now(timezone.utc).replace(microsecond=0))
        self.summary = {"observed": alive_total, "assets": len(ASSETS), "new": len(new)}
        self.store.log_scan(p.to_dict(), len(new))
        return self.summary

    self.scan_task = asyncio.create_task(job())
    return self.scan_task


Runtime.start_scan = fake_start_scan

# --------------------------------------------------------------------------- envío simulado
STATUSES = {"fw-matriz": "matched", "sw-core-01": "matched", "srv-archivos": "matched", "dc01": "matched",
            "pve-01": "matched", "nas-respaldos": "matched", "ups-rack": "matched", "pc-contab-01": "matched",
            "pc-contab-02": "matched", "pc-recepcion": "matched", "pc-direccion": "matched",
            "prn-contabilidad": "matched", "prn-direccion": "matched", "lap-atorres": "matched"}


def fake_sync_all(store_, only_changed=False):
    assets = store_.list_assets()
    now = iso(datetime.now(timezone.utc).replace(microsecond=0) + timedelta(seconds=1))
    results: dict[str, int] = {}
    for a in assets:
        a.synced_at = now
        a.remote_status = STATUSES.get(a.hostname, "created_pending")
        a.remote_reason = "ligado a un activo existente" if a.remote_status == "matched" else "en la bandeja Descubiertos"
        results[a.remote_status] = results.get(a.remote_status, 0) + 1
    store_.save_assets(assets)
    return {"sent": len(assets), "batches": [{"id": "demo"}], "results": results}


service.sync_all = fake_sync_all

if __name__ == "__main__":
    print(f"Demo en http://127.0.0.1:{args.port}/ (datos en {DATA})", file=sys.stderr)
    uvicorn.run(create_app(bind_host="127.0.0.1", port=args.port), host="127.0.0.1", port=args.port, log_level="warning")
