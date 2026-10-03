"""The /vulnbox Blueprint, offline. Role gating itself is covered by the shared
matrix in tests/test_routes_roles.py; this file covers behavior: the private
key never in JSON, 409 on concurrent jobs, audit entries, and the /config
writers."""

import threading
import time

import pytest

import app_config
import audit
from vulnbox import preflight, recon


@pytest.fixture
def team3(monkeypatch):
    """Configure team_id=3 → vulnbox 10.60.3.2, bypassing the 5s config cache."""
    monkeypatch.setitem(app_config.DEFAULTS, "team_id", "3")
    app_config.invalidate()
    yield
    app_config.invalidate()


@pytest.fixture
def audit_calls(monkeypatch):
    calls = []
    monkeypatch.setattr(audit, "log", lambda actor, action, **kw: calls.append(action))
    return calls


@pytest.fixture
def recorded_sets(monkeypatch):
    calls = []
    monkeypatch.setattr(app_config, "set", lambda key, value: calls.append((key, value)))
    return calls


def wait_job(client, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        cur = client.get("/vulnbox").get_json()["jobs"]["current"]
        if cur and cur["state"] != "running":
            return cur
        time.sleep(0.02)
    raise AssertionError("job did not finish")


# --- overview -----------------------------------------------------------------

def test_overview_for_viewer_with_unconfigured_team(viewer):
    body = viewer.get("/vulnbox").get_json()
    assert body["key"] == {"exists": False}
    assert body["target"]["host"] is None
    assert "team id" in body["target"]["error"]
    assert body["jobs"] == {"current": None, "last": {}}
    assert body["defaults"]["values"]["tick_length"] == 60000


def test_overview_resolves_target_from_team_id(viewer, team3):
    target = viewer.get("/vulnbox").get_json()["target"]
    assert target["host"] == "10.60.3.2"
    assert target["user"] == "root" and target["port"] == 22


# --- key: the private half is download-only -------------------------------------

def test_generate_returns_public_key_only(admin, audit_calls):
    resp = admin.post("/vulnbox/key", json={})
    assert resp.status_code == 201
    body = resp.get_json()
    assert body["public_key"].startswith("ssh-ed25519 ")
    assert "PRIVATE KEY" not in resp.get_data(as_text=True)
    assert "PRIVATE KEY" not in admin.get("/vulnbox").get_data(as_text=True)
    assert audit_calls == ["vulnbox.key_generate"]


def test_private_key_is_a_no_store_attachment(admin, audit_calls):
    admin.post("/vulnbox/key", json={})
    resp = admin.get("/vulnbox/key/private")
    assert resp.status_code == 200
    assert "attachment" in resp.headers["Content-Disposition"]
    assert resp.headers["Cache-Control"] == "no-store"
    assert "OPENSSH PRIVATE KEY" in resp.get_data(as_text=True)
    assert "vulnbox.key_download" in audit_calls


def test_second_generate_needs_rotate(admin, audit_calls):
    first = admin.post("/vulnbox/key", json={}).get_json()
    assert admin.post("/vulnbox/key", json={}).status_code == 409
    resp = admin.post("/vulnbox/key", json={"rotate": True})
    assert resp.status_code == 201
    assert resp.get_json()["fingerprint"] != first["fingerprint"]
    assert audit_calls[-1] == "vulnbox.key_rotate"


def test_private_key_404_when_none(admin):
    assert admin.get("/vulnbox/key/private").status_code == 404


# --- jobs ---------------------------------------------------------------------------

def test_job_without_target_is_400(operator):
    resp = operator.post("/vulnbox/recon")
    assert resp.status_code == 400
    assert "team id" in resp.get_json()["error"]


def test_preflight_without_key_finishes_without_network(operator, team3, audit_calls):
    resp = operator.post("/vulnbox/preflight")
    assert resp.status_code == 202
    done = wait_job(operator)
    checks = {c["name"]: c["status"] for c in done["result"]["checks"]}
    assert checks["key"] == "fail" and checks["reachable"] == "skipped"
    assert audit_calls == ["vulnbox.preflight"]


def test_concurrent_job_is_409(operator, team3, monkeypatch):
    gate = threading.Event()

    def slow(target):
        gate.wait(5)
        return []
    monkeypatch.setattr(preflight, "run", slow)
    assert operator.post("/vulnbox/preflight").status_code == 202
    resp = operator.post("/vulnbox/recon")
    assert resp.status_code == 409
    assert resp.get_json()["running"] == "preflight"
    gate.set()
    wait_job(operator)


def test_key_rotation_refused_while_a_job_runs(admin, team3, monkeypatch):
    admin.post("/vulnbox/key", json={})
    gate = threading.Event()
    monkeypatch.setattr(preflight, "run", lambda t: gate.wait(5) and [])
    admin.post("/vulnbox/preflight")
    assert admin.post("/vulnbox/key", json={"rotate": True}).status_code == 409
    gate.set()
    wait_job(admin)


# --- /config writers -------------------------------------------------------------------

def test_import_needs_a_finished_recon(admin):
    assert admin.post("/vulnbox/import-services").status_code == 409


def test_import_upserts_recon_game_services(admin, team3, monkeypatch, recorded_sets, audit_calls):
    monkeypatch.setattr(recon, "run", lambda t: {
        "services": [{"name": "notes", "ports": [9001, 5432], "game_ports": [9001], "containers": []}],
        "notes": [],
    })
    assert admin.post("/vulnbox/recon").status_code == 202
    wait_job(admin)
    resp = admin.post("/vulnbox/import-services")
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["added"] + body["updated"] == 1
    key, saved = recorded_sets[-1]
    assert key == "services"
    assert {"name": "notes", "ip": "10.60.3.2", "port": 9001,
            "notes": "imported from recon"} in saved
    assert "vulnbox.import_services" in audit_calls


def test_seed_defaults_applies_ecsc_values(admin, recorded_sets, audit_calls):
    resp = admin.post("/vulnbox/seed-defaults")
    assert resp.status_code == 200
    body = resp.get_json()
    saved = dict(recorded_sets)
    assert saved["tick_length"] == 60000
    assert saved["flag_lifetime"] == 5
    assert saved["flag_regex"] == r"ECSC\{[A-Za-z0-9_-]{32}\}"
    assert not saved["flag_regex"].startswith("^")  # must match inside traffic
    assert body["env"]["TICK_LENGTH"] == "60000"
    assert body["env"]["TICK_START"] == "2026-10-15T09:00:00Z"
    assert audit_calls == ["vulnbox.seed_defaults"]


def test_seed_defaults_without_database_is_503(admin):
    resp = admin.post("/vulnbox/seed-defaults")
    assert resp.status_code == 503
