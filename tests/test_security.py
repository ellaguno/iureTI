"""Cada prueba reproduce un ataque del análisis de seguridad y comprueba que ya está bloqueado."""

import httpx
import pytest
from fastapi.testclient import TestClient

from iureti_discovery import enrich, security
from iureti_discovery.agent import Agent
from iureti_discovery.models import Asset
from iureti_discovery.runtime import Runtime
from iureti_discovery.snmp import SnmpCredential
from iureti_discovery.store import Store
from iureti_discovery.sync import csv_safe, to_import_csv
from iureti_discovery.web.app import create_app


# ── C2 / rebinding / CSRF / token ──────────────────────────────────────────
def local(db, **kw):
    return TestClient(create_app(db, **kw), base_url="http://127.0.0.1:8765", headers={"X-Iureti-UI": "1"})


def test_host_header_allowlist_blocks_rebinding(tmp_path):
    c = local(str(tmp_path / "t.db"))
    assert c.get("/api/status", headers={"host": "rebind.atacante.com"}).status_code == 400
    assert c.get("/api/status").status_code == 200  # Host correcto


def test_api_requires_own_header_blocks_csrf(tmp_path):
    c = TestClient(create_app(str(tmp_path / "t.db")), base_url="http://127.0.0.1:8765")  # sin la cabecera
    assert c.post("/api/sync").status_code == 403
    assert c.put("/api/settings", json={}).status_code == 403
    assert c.post("/api/enrich").status_code == 403


def test_cross_origin_is_rejected(tmp_path):
    c = local(str(tmp_path / "t.db"))
    assert c.post("/api/sync", headers={"origin": "https://sitio-malicioso.com"}).status_code == 403


def test_token_required_when_exposed(tmp_path):
    db = str(tmp_path / "t.db")
    app = create_app(db, bind_host="0.0.0.0", port=8765)
    token = Store(db).get_settings()["ui_token"]
    assert token
    c = TestClient(app, base_url="http://192.168.1.5:8765", headers={"X-Iureti-UI": "1", "host": "192.168.1.5:8765"})
    assert c.get("/api/status").status_code == 401                       # sin token
    assert c.get("/api/status", headers={"X-Iureti-Token": token}).status_code == 200
    assert c.get("/api/status", headers={"X-Iureti-Token": "malo"}).status_code == 401


def test_security_headers_and_no_docs(tmp_path):
    c = local(str(tmp_path / "t.db"))
    h = c.get("/").headers
    assert "default-src 'none'" in h["content-security-policy"] and h["x-frame-options"] == "DENY"
    assert h["x-content-type-options"] == "nosniff"
    assert c.get("/openapi.json").status_code == 404 and c.get("/docs").status_code == 404


def test_ui_token_never_leaves_via_api(tmp_path):
    c = local(str(tmp_path / "t.db"))
    assert "ui_token" not in c.get("/api/settings").json()
    # tampoco es escribible desde la API
    c.put("/api/settings", json={"ui_token": "inyectado"})
    assert Store(c.app.state._db if False else str(tmp_path / "t.db")).get_settings()["ui_token"] != "inyectado"


# ── A1: token no se reutiliza al cambiar de URL ────────────────────────────
def test_token_cleared_when_api_url_changes(tmp_path):
    db = str(tmp_path / "t.db")
    c = local(db)
    c.put("/api/settings", json={"api_url": "https://legit.iurefficient.com", "api_token": "iurprobe_SECRETO"})
    masked = c.get("/api/settings").json()
    # El atacante cambia la URL reenviando el token enmascarado
    c.put("/api/settings", json={**masked, "api_url": "https://atacante.example"})
    st = Store(db).get_settings()
    assert st["api_url"] == "https://atacante.example" and st["api_token"] == ""


def test_api_url_must_be_https(tmp_path):
    c = local(str(tmp_path / "t.db"))
    assert c.put("/api/settings", json={"api_url": "http://atacante.example"}).status_code == 400
    assert c.put("/api/settings", json={"api_url": "https://cliente.iurefficient.com"}).status_code == 200
    assert c.put("/api/settings", json={"api_url": "http://127.0.0.1:5000"}).status_code == 200   # on-prem local
    assert c.put("/api/settings", json={"api_url": "http://10.0.0.5"}).status_code == 200          # on-prem LAN


def test_settings_bounds(tmp_path):
    c = local(str(tmp_path / "t.db"))
    assert c.put("/api/settings", json={"concurrency": 10**7}).status_code == 400
    assert c.put("/api/settings", json={"tcp_timeout": 0.0001}).status_code == 400
    assert c.put("/api/settings", json={"allowed_networks": ["no-es-cidr"]}).status_code == 400
    assert c.put("/api/settings", json={"allowed_networks": ["192.168.0.0/16"]}).status_code == 200


# ── A2: configuración remota acotada ───────────────────────────────────────
def test_remote_config_cannot_scan_the_internet(tmp_path):
    db = str(tmp_path / "t.db")
    agent = Agent(Runtime(Store(db)))
    agent.apply_config({"targets": ["8.8.8.0/24"], "concurrency": 50000, "tcp_timeout": 0.001,
                        "heartbeat_seconds": 1, "schedule": {"interval_minutes": 1}}, "c-1")
    s = Store(db).get_settings()
    assert s["targets"] == []                       # rango público rechazado
    assert s["concurrency"] == security.MAX_CONCURRENCY
    assert s["tcp_timeout"] == security.MIN_TCP_TIMEOUT
    assert s["heartbeat_seconds"] == security.MIN_HEARTBEAT
    assert s["schedule_interval_minutes"] == security.MIN_SCHEDULE_INTERVAL


def test_remote_config_accepts_private_ranges(tmp_path):
    db = str(tmp_path / "t.db")
    agent = Agent(Runtime(Store(db)))
    agent.apply_config({"targets": ["192.168.10.0/24"], "concurrency": 128}, "c-2")
    s = Store(db).get_settings()
    assert s["targets"] == ["192.168.10.0/24"] and s["concurrency"] == 128


# ── C1: credenciales SNMP acotadas por subred ──────────────────────────────
def test_snmp_credential_scoped_to_subnet():
    cred = SnmpCredential(name="core", community="secreta", networks=["10.0.10.0/24"])
    assert cred.applies_to("10.0.10.5")
    assert not cred.applies_to("192.168.1.5")       # no se manda la community fuera de su VLAN
    assert SnmpCredential(name="x").applies_to("1.2.3.4")  # sin subredes = todas (compatibilidad)


# ── A3: enlaces javascript:/data: ──────────────────────────────────────────
def test_malicious_scheme_links_rejected():
    assert not security.is_safe_link("javascript:alert(1)")
    assert not security.is_safe_link("data:text/html,<script>")
    assert security.is_safe_link("https://e.huawei.com/x")
    r = enrich.normalize_report({"identified": True, "model": "x", "product_url": "javascript:alert(1)",
                                 "image_url": "data:x"})
    assert r["product_url"] == "" and r["image_url"] == ""


# ── A4: SSRF por URL interna o por redirección ─────────────────────────────
def test_internal_urls_are_not_fetched():
    assert security.resolve_safe_target("http://192.168.100.1/reboot.cgi") is None
    assert security.resolve_safe_target("http://127.0.0.1/x") is None
    assert security.resolve_safe_target("http://[::1]/x") is None
    assert security.resolve_safe_target("file:///etc/passwd") is None


def test_ssrf_redirect_to_internal_is_blocked(monkeypatch):
    # El primer host es "público" (lo fingimos) pero redirige a la red interna: no debe seguirse.
    monkeypatch.setattr(security, "resolve_safe_target",
                        lambda url: ("203.0.113.9", "cdn.example") if "cdn.example" in url else None)
    hits = []

    def handler(request):
        hits.append(str(request.url))
        return httpx.Response(302, headers={"location": "http://192.168.100.1/admin"})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    assert enrich.download_image(client, "https://cdn.example/foto.jpg") == ""
    assert all("192.168.100.1" not in u for u in hits)  # nunca se conectó a la IP interna


# ── M2: inyección de fórmulas en CSV ───────────────────────────────────────
def test_csv_formula_injection_neutralised():
    assert csv_safe('=HYPERLINK("http://x","clic")').startswith("'=")
    assert csv_safe("+1") == "'+1" and csv_safe("@SUM(A1)") == "'@SUM(A1)"
    assert csv_safe("Laptop Dell") == "Laptop Dell"
    row = to_import_csv([Asset(hostname='=cmd|calc', ips=["1.1.1.1"])]).decode("utf-8-sig").splitlines()[1]
    assert "=cmd" not in row.split(",")[1].strip('"') or row.split(",")[1].strip('"').startswith("'")
