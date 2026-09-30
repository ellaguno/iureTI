import csv
import io

import pytest
from fastapi.testclient import TestClient

from iureti_discovery import sync
from iureti_discovery.models import Asset
from iureti_discovery.store import Store
from iureti_discovery.web.app import MASK, create_app


def _asset(**kw):
    base = dict(device_type="switch", hostname="sw-core-01.corp.local", ips=["10.0.0.2"],
                macs=["00:1a:2b:3c:4d:5e"], vendor="Cisco Systems, Inc", model="C9300-48P",
                serial="FCW1", fingerprint="serial:FCW1")
    base.update(kw)
    return Asset(**base)


def test_import_csv_uses_inventory_template_headers():
    rows = list(csv.DictReader(io.StringIO(sync.to_import_csv([_asset()]).decode("utf-8-sig"))))
    assert list(rows[0].keys())[:9] == ["SKU", "Nombre", "Tipo", "Estado", "Categoría", "Ubicación", "Marca", "Modelo", "Serie"]
    r = rows[0]
    assert r["Nombre"] == "sw-core-01" and r["Tipo"] == "Hardware" and r["Serie"] == "FCW1"
    # Lo capturado a mano no se toca: esas celdas van vacías
    assert r["Ubicación"] == r["Notas"] == r["Responsable"] == r["Categoría"] == r["Estado"] == ""
    assert "Switch" in r["Descripción"] and "10.0.0.2" in r["Descripción"]


def test_suggested_name_without_hostname():
    a = _asset(hostname="", vendor="(MAC aleatoria/local)", model="", device_type="printer", ips=["10.0.0.9"])
    assert sync.suggested_name(a) == "Impresora (10.0.0.9)"


def test_batch_and_results():
    a = _asset()
    batch = sync.build_batch([a], {"probe_id": "sonda-1", "site": "Matriz"})
    assert batch["probe"]["id"] == "sonda-1" and batch["assets"][0]["probe_asset_id"] == a.id
    changed = sync.apply_results([a], {"results": [{"probe_asset_id": a.id, "status": "matched", "inventory_id": "7b0c-uuid"}]})
    assert changed[0].remote_status == "matched" and a.inventory_id == "7b0c-uuid" and a.synced_at


def test_rejected_is_not_marked_synced():
    a = _asset()
    sync.apply_results([a], {"results": [{"probe_asset_id": a.id, "status": "rejected", "reason": "sin datos"}]})
    assert a.remote_status == "rejected" and not a.synced_at and a.remote_reason == "sin datos"


def test_send_batch_uses_plugin_route(monkeypatch):
    seen = {}

    class Resp:
        status_code, content = 202, b"{}"

        def json(self):
            return {}

    def fake_post(url, json, headers, timeout):
        seen.update(url=url, auth=headers["Authorization"])
        return Resp()

    monkeypatch.setattr(sync.httpx, "post", fake_post)
    sync.send_batch({"assets": []}, "https://x.example/", "iurprobe_abc")
    assert seen == {"url": "https://x.example/api/plugins/inventory/discovery/batches", "auth": "Bearer iurprobe_abc"}


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "t.db")


@pytest.fixture
def client(db_path):
    return TestClient(create_app(db_path))


def test_settings_secrets_are_masked_and_preserved(client, db_path):
    creds = [{"name": "core", "version": "2c", "community": "s3cret"}]
    r = client.put("/api/settings", json={"snmp_credentials": creds, "api_token": "iurprobe_x"}).json()
    assert r["snmp_credentials"][0]["community"] == MASK and r["api_token"] == MASK
    # Reenviar lo enmascarado conserva el secreto real
    client.put("/api/settings", json=r)
    stored = Store(db_path).get_settings()
    assert stored["snmp_credentials"][0]["community"] == "s3cret" and stored["api_token"] == "iurprobe_x"


def test_settings_validation(client):
    assert client.put("/api/settings", json={"snmp_credentials": [{"name": "", "version": "2c"}]}).status_code == 400
    assert client.put("/api/settings", json={"snmp_credentials": [{"name": "x", "version": "1"}]}).status_code == 400


def test_scan_rejects_bad_targets(client):
    assert client.post("/api/scans", json={"targets": ["10.0.0.0/8"]}).status_code == 400
    assert client.post("/api/scans", json={"targets": []}).status_code == 400


def test_status_and_exports(client):
    st = client.get("/api/status").json()
    assert st["counts"] == {"total": 0, "unsynced": 0} and st["device_types"]["printer"] == "Impresora"
    assert client.get("/api/export.csv").content.decode("utf-8-sig").startswith("SKU,Nombre,Tipo")
    assert client.get("/api/export.json").json()["assets"] == []
    assert client.post("/api/sync").status_code == 200  # sin activos no llama a la API
