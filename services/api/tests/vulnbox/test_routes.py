"""The /vulnbox Blueprint, offline. Role gating itself is covered by the shared
matrix in tests/test_routes_roles.py; this file covers behavior: the private
key never in JSON, 409 on concurrent jobs, audit entries, and the /config
writers. Presets are tested with a test-only preset, never a real game's."""

import threading
import time

import pytest

import app_config
import audit
from vulnbox import preflight, presets, recon

TEST_PRESET = presets.Preset(
    id="test-game",
    name="Test game",
    values={
        "tick_length": 120000,
        "flag_lifetime": 3,
        "flag_regex": r"FLAG\{[a-f0-9]{32}\}",
        "start_date": "2000-01-01T00:00:00Z",
        "vulnbox_service_ports": "10000-10100",
    },
)


def set_config(monkeypatch, **values):
    """Point /config defaults at `values`, bypassing the 5s config cache."""
    for key, value in values.items():
        monkeypatch.setitem(app_config.DEFAULTS, key, value)
    app_config.invalidate()


@pytest.fixture(autouse=True)
def _fresh_config_cache():
    app_config.invalidate()
    yield
    app_config.invalidate()


@pytest.fixture
def vm_ip(monkeypatch):
    set_config(monkeypatch, vm_ip="192.0.2.10")


@pytest.fixture
def test_preset(monkeypatch):
    monkeypatch.setattr(presets, "PRESETS", (TEST_PRESET,))
    return TEST_PRESET


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

def test_overview_with_no_vulnbox_address_says_how_to_fix_it(viewer, monkeypatch, test_preset):
    set_config(monkeypatch, vm_ip="")
    body = viewer.get("/vulnbox").get_json()
    assert body["key"] == {"exists": False}
    assert body["target"]["host"] is None
    assert "vm_ip" in body["target"]["error"]
    assert body["jobs"] == {"current": None, "last": {}}
    assert [p["id"] for p in body["presets"]] == ["test-game"]
    assert body["presets"][0]["applied"] is False


def test_overview_resolves_target_from_vm_ip(viewer, vm_ip):
    target = viewer.get("/vulnbox").get_json()["target"]
    assert target["host"] == "192.0.2.10"
    assert target["user"] == "root" and target["port"] == 22


def test_overview_marks_a_preset_applied_when_config_matches(viewer, monkeypatch, test_preset):
    set_config(monkeypatch, **test_preset.values)
    assert viewer.get("/vulnbox").get_json()["presets"][0]["applied"] is True


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

def test_job_without_target_is_400(operator, monkeypatch):
    set_config(monkeypatch, vm_ip="")
    resp = operator.post("/vulnbox/recon")
    assert resp.status_code == 400
    assert "vm_ip" in resp.get_json()["error"]


def test_preflight_without_key_finishes_without_network(operator, vm_ip, audit_calls):
    resp = operator.post("/vulnbox/preflight")
    assert resp.status_code == 202
    done = wait_job(operator)
    checks = {c["name"]: c["status"] for c in done["result"]["checks"]}
    assert checks["key"] == "fail" and checks["reachable"] == "skipped"
    assert audit_calls == ["vulnbox.preflight"]


def test_concurrent_job_is_409(operator, vm_ip, monkeypatch):
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


def test_key_rotation_refused_while_a_job_runs(admin, vm_ip, monkeypatch):
    admin.post("/vulnbox/key", json={})
    gate = threading.Event()
    monkeypatch.setattr(preflight, "run", lambda t: gate.wait(5) and [])
    admin.post("/vulnbox/preflight")
    assert admin.post("/vulnbox/key", json={"rotate": True}).status_code == 409
    gate.set()
    wait_job(admin)


def test_recon_gets_the_configured_service_ports(operator, vm_ip, monkeypatch):
    set_config(monkeypatch, vulnbox_service_ports="10000-10100,31337")
    seen = {}

    def fake_run(target, ports):
        seen["ports"] = ports
        return {"services": [], "notes": []}
    monkeypatch.setattr(recon, "run", fake_run)
    assert operator.post("/vulnbox/recon").status_code == 202
    wait_job(operator)
    assert seen["ports"] == ((10000, 10100), (31337, 31337))


def test_recon_with_an_invalid_stored_port_setting_is_400(operator, vm_ip, monkeypatch):
    set_config(monkeypatch, vulnbox_service_ports="not-a-port")
    resp = operator.post("/vulnbox/recon")
    assert resp.status_code == 400
    assert "vulnbox_service_ports" in resp.get_json()["error"]


# --- /config writers -------------------------------------------------------------------

def test_import_needs_a_finished_recon(admin):
    assert admin.post("/vulnbox/import-services").status_code == 409


def test_import_upserts_recon_service_ports(admin, vm_ip, monkeypatch, recorded_sets, audit_calls):
    monkeypatch.setattr(recon, "run", lambda t, ports: {
        "services": [{"name": "notes", "ports": [10001, 5432], "service_ports": [10001],
                      "containers": []}],
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
    assert {"name": "notes", "ip": "192.0.2.10", "port": 10001,
            "notes": "imported from recon"} in saved
    assert "vulnbox.import_services" in audit_calls


def test_apply_preset_writes_its_values_and_returns_env_lines(admin, test_preset,
                                                              recorded_sets, audit_calls):
    resp = admin.post(f"/vulnbox/presets/{test_preset.id}")
    assert resp.status_code == 200
    body = resp.get_json()
    assert dict(recorded_sets) == {
        k: app_config.coerce_scalar(k, v) for k, v in test_preset.values.items()
    }
    # only the settings the assembler reads at boot become .env lines
    assert body["env"] == {
        "FLAG_REGEX": r"FLAG\{[a-f0-9]{32}\}",
        "TICK_LENGTH": "120000",
        "TICK_START": "2000-01-01T00:00:00Z",
        "FLAG_LIFETIME": "3",
    }
    assert audit_calls == ["vulnbox.apply_preset"]


def test_unknown_preset_is_404(admin, test_preset):
    assert admin.post("/vulnbox/presets/no-such-game").status_code == 404


def test_apply_preset_without_database_is_503(admin, test_preset):
    assert admin.post(f"/vulnbox/presets/{test_preset.id}").status_code == 503


def test_unusable_data_dir_is_a_clear_503(admin, vm_ip, tmp_path, monkeypatch):
    """A missing/read-only ./vulnbox-data mount must answer with a message,
    not a 500 traceback. A path under a regular file can't be created."""
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("")
    monkeypatch.setenv("W4RYA_VULNBOX_DIR", str(blocker / "vulnbox-data"))
    for method, path, body in (("POST", "/vulnbox/key", {}), ("POST", "/vulnbox/preflight", None)):
        resp = admin.open(path, method=method, json=body)
        assert resp.status_code == 503, (path, resp.status_code)
        assert "data dir unavailable" in resp.get_json()["error"]
