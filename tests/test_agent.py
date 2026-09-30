import json
from datetime import datetime, timedelta

import httpx
import pytest

from iureti_discovery.agent import Agent, in_window, parse_window, version_tuple
from iureti_discovery.runtime import Runtime
from iureti_discovery.store import Store


def test_windows():
    assert parse_window("01:00-05:00") == (60, 300) and parse_window("bad") is None
    at = lambda h, m=0: datetime(2026, 9, 30, h, m)  # noqa: E731
    assert in_window("", at(13)) and in_window("01:00-05:00", at(3)) and not in_window("01:00-05:00", at(5))
    assert in_window("22:00-02:00", at(23)) and in_window("22:00-02:00", at(1)) and not in_window("22:00-02:00", at(12))


def test_version_tuple():
    assert version_tuple("0.10.0") > version_tuple("0.9.3")


@pytest.fixture
def rt(tmp_path):
    store = Store(tmp_path / "t.db")
    store.update_settings({"api_url": "https://x.example", "api_token": "iurprobe_t", "targets": ["10.0.0.0/30"]})
    return Runtime(store)


def make_agent(rt, handler, now=None):
    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return Agent(rt, http=http, now=now or datetime.now)


async def test_heartbeat_applies_config_and_queues_commands(rt):
    seen = []

    def handler(request):
        seen.append((str(request.url), request.headers["authorization"], json.loads(request.content)))
        return httpx.Response(200, json={
            "config_version": "c-1",
            "config": {"targets": ["10.0.1.0/24"], "schedule": {"interval_minutes": 360, "window": "01:00-05:00"},
                       "collectors": {"mdns": False, "snmp": False}, "auto_enrich": True, "heartbeat_seconds": 120},
            "commands": [{"id": "cmd-1", "type": "reboot_now"}],
            "latest_version": "9.9.9",
        })

    agent = make_agent(rt, handler)
    await agent.heartbeat()
    url, auth, body = seen[0]
    assert url == "https://x.example/api/plugins/inventory/discovery/heartbeat" and auth == "Bearer iurprobe_t"
    assert body["probe"]["version"] and body["status"]["state"] == "idle" and body["config_version"] == ""
    s = rt.store.get_settings()
    assert s["managed"] and s["config_version"] == "c-1" and s["targets"] == ["10.0.1.0/24"]
    assert s["schedule_interval_minutes"] == 360 and s["schedule_window"] == "01:00-05:00"
    assert s["use_mdns"] is False and s["snmp_enabled"] is False and s["auto_enrich"] is True
    assert s["heartbeat_seconds"] == 120 and agent.state["connected"] and agent.state["latest_version"] == "9.9.9"
    # orden desconocida → ack «ignored», que viaja en el siguiente heartbeat y luego se descarta
    await agent.execute(agent.commands.get_nowait())
    await agent.heartbeat()
    assert seen[1][2]["acks"] == [{"id": "cmd-1", "status": "ignored", "detail": "orden desconocida: reboot_now"}]
    await agent.heartbeat()
    assert seen[2][2]["acks"] == []


async def test_invalid_targets_from_server_are_ignored(rt):
    agent = make_agent(rt, lambda r: httpx.Response(200, json={"config": {"targets": ["10.0.0.0/8"]}}))
    await agent.heartbeat()
    assert rt.store.get_settings()["targets"] == ["10.0.0.0/30"]


@pytest.mark.parametrize("status,needle", [(404, "modo local"), (401, "Token"), (500, "500")])
async def test_heartbeat_errors_keep_local_mode(rt, status, needle):
    agent = make_agent(rt, lambda r: httpx.Response(status))
    await agent.heartbeat()
    assert not agent.state["connected"] and needle in agent.state["error"]


async def test_scan_now_command_runs_scan_and_syncs(rt, monkeypatch):
    calls = []

    async def fake_scan(targets, use_snmp=True, remember=True):
        calls.append(("scan", targets, use_snmp, remember))
        return {"observed": 3, "new": 1}

    async def fake_sync(only_changed=False):
        calls.append(("sync", only_changed))
        return {"sent": 3}

    monkeypatch.setattr(rt, "scan", fake_scan)
    monkeypatch.setattr(rt, "sync", fake_sync)
    agent = make_agent(rt, lambda r: httpx.Response(200, json={}))
    await agent.execute({"id": "c9", "type": "scan_now", "args": {"targets": ["10.0.0.4"]}})
    assert calls == [("scan", ["10.0.0.4"], True, False), ("sync", False)]
    assert agent.acks == [{"id": "c9", "status": "done", "detail": "3 hosts vivos, 1 nuevos"}]


def test_schedule_due(rt):
    now = datetime(2026, 9, 30, 3, 0)
    agent = Agent(rt, now=lambda: now)
    assert not agent.schedule_due()  # sin programación
    rt.store.update_settings({"schedule_interval_minutes": 60, "schedule_window": "01:00-05:00"})
    assert agent.schedule_due()  # nunca ha escaneado
    started = (now - timedelta(minutes=30)).astimezone().isoformat()
    rt.store.log_scan({"started_at": started, "finished_at": started, "targets": [], "phase": "terminado",
                       "alive": 0, "error": ""}, 0)
    assert not agent.schedule_due()  # hace 30 min
    agent.now = lambda: now + timedelta(minutes=45)
    assert agent.schedule_due()  # ya pasó una hora
    agent.now = lambda: now + timedelta(hours=3)
    assert not agent.schedule_due()  # fuera de la ventana
