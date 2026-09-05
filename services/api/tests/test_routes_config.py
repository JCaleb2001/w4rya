"""The /config endpoints, offline.

`app_config._pool` is never wired in the test suite (that only happens in
`create_app()`), so `app_config.get()` falls straight through to DEFAULTS and
every read endpoint works with no database at all.

Writes are a different matter: `app_config.set()` raises without a pool. Rather
than inject a fake pool — which would leave real values in `app_config._cache`,
a module global shared by every test in the session — the two tests that need a
successful PUT monkeypatch `app_config.set` itself and assert on what it was
handed. Everything else here is a validation failure, which returns before any
write is attempted.
"""

import pytest

import app_config


@pytest.fixture
def recorded_sets(monkeypatch):
    """Capture app_config.set(key, value) calls instead of persisting them."""
    calls: list[tuple[str, object]] = []
    monkeypatch.setattr(app_config, "set", lambda key, value: calls.append((key, value)))
    return calls


# --- reads -----------------------------------------------------------------

def test_get_config_returns_exactly_the_documented_scalar_keys(viewer):
    """The Config page's Game tab renders one field per key; a key appearing
    or vanishing here is a frontend contract change."""
    resp = viewer.get("/config")
    assert resp.status_code == 200
    body = resp.get_json()
    assert set(body) == app_config.SCALAR_KEYS


def test_get_config_falls_back_to_defaults_with_no_database(viewer):
    body = viewer.get("/config").get_json()
    assert body["flag_regex"] == app_config.DEFAULTS["flag_regex"]
    assert isinstance(body["tick_length"], int)
    assert isinstance(body["flag_lifetime"], int)
    assert body["rules_autoreload"] is False


def test_get_config_is_readable_by_a_viewer_but_writing_is_not(viewer):
    assert viewer.get("/config").status_code == 200
    assert viewer.put("/config", json={"vm_ip": "10.0.0.1"}).status_code == 403


def test_get_config_services_returns_the_seeded_service_shape(viewer):
    resp = viewer.get("/config/services")
    assert resp.status_code == 200
    services = resp.get_json()
    assert isinstance(services, list) and services
    for entry in services:
        assert set(entry) == {"name", "ip", "port", "notes"}
        assert isinstance(entry["port"], int)


def test_get_config_teams_defaults_to_empty(viewer):
    resp = viewer.get("/config/teams")
    assert resp.status_code == 200
    assert resp.get_json() == []


def test_services_and_config_services_agree(viewer):
    """`GET /services` is the legacy path the frontend still calls; both read
    the same config row."""
    assert viewer.get("/services").get_json() == viewer.get("/config/services").get_json()


# --- PUT /config validation ------------------------------------------------

def test_put_config_rejects_an_unknown_field(admin, recorded_sets):
    resp = admin.put("/config", json={"totally_made_up": "x"})
    assert resp.status_code == 400
    body = resp.get_json()
    assert body["error"] == "invalid fields"
    assert body["fields"] == {"totally_made_up": "unknown key"}
    assert recorded_sets == []


def test_put_config_rejects_a_non_object_body(admin, recorded_sets):
    resp = admin.put("/config", json=["flag_regex", "x"])
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "expected an object"
    assert recorded_sets == []


def test_put_config_rejects_an_unparseable_flag_regex(admin, recorded_sets):
    """Write-time validation exists because a broken flag_regex breaks /query
    for the whole team, and the failure surfaces far from the edit."""
    resp = admin.put("/config", json={"flag_regex": "FLAG{[a-z"})
    assert resp.status_code == 400
    assert "invalid regex" in resp.get_json()["fields"]["flag_regex"]
    assert recorded_sets == []


def test_put_config_rejects_a_redos_prone_flag_regex(admin, recorded_sets):
    """(x+)+ compiles fine but can freeze every /query with catastrophic
    backtracking, so the heuristic rejects nested unbounded quantifiers."""
    resp = admin.put("/config", json={"flag_regex": "(a+)+="})
    assert resp.status_code == 400
    assert "nested unbounded quantifiers" in resp.get_json()["fields"]["flag_regex"]
    assert recorded_sets == []


def test_put_config_rejects_a_non_numeric_tick_length(admin, recorded_sets):
    resp = admin.put("/config", json={"tick_length": "not-a-number"})
    assert resp.status_code == 400
    assert "tick_length" in resp.get_json()["fields"]
    assert recorded_sets == []


def test_put_config_reports_every_bad_field_at_once(admin, recorded_sets):
    resp = admin.put("/config", json={"tick_length": "nope", "mystery": 1})
    assert resp.status_code == 400
    assert set(resp.get_json()["fields"]) == {"tick_length", "mystery"}


def test_put_config_coerces_scalars_before_storing_them(admin, recorded_sets):
    resp = admin.put("/config", json={
        "tick_length": "5000",
        "rules_autoreload": "on",
        "vm_ip": "10.0.0.9",
    })
    assert resp.status_code == 200
    assert dict(recorded_sets) == {
        "tick_length": 5000,
        "rules_autoreload": True,
        "vm_ip": "10.0.0.9",
    }


def test_a_partially_invalid_put_still_writes_the_valid_fields(admin, recorded_sets):
    # FINDING: PUT /config is not atomic. The handler sets each valid key as it
    # walks the payload and only checks `errors` at the end, so a body with one
    # bad field returns 400 while the good fields have already been persisted.
    # The Config page sends the whole form at once, so an admin who fixes the
    # rejected field and resubmits is re-applying values that silently went
    # live on the failed attempt. Pinning current behaviour.
    resp = admin.put("/config", json={"vm_ip": "10.9.9.9", "flag_regex": "FLAG{[a-z"})
    assert resp.status_code == 400
    assert dict(recorded_sets) == {"vm_ip": "10.9.9.9"}


# --- PUT /config/services validation ---------------------------------------

def test_put_services_rejects_a_non_list(admin, recorded_sets):
    resp = admin.put("/config/services", json={"name": "web", "ip": "10.0.0.1", "port": 80})
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "expected a list"
    assert recorded_sets == []


def test_put_services_rejects_a_non_object_entry(admin, recorded_sets):
    resp = admin.put("/config/services", json=["web"])
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "service entry must be an object"
    assert recorded_sets == []


@pytest.mark.parametrize("entry,expected", [
    ({"ip": "10.0.0.1", "port": 80}, "invalid service name"),
    ({"name": "web;drop", "ip": "10.0.0.1", "port": 80}, "invalid service name"),
    ({"name": "x" * 65, "ip": "10.0.0.1", "port": 80}, "invalid service name"),
    ({"name": "web", "ip": "", "port": 80}, "service ip is required"),
    ({"name": "web", "ip": "10.0.0.1", "port": "eighty"}, "invalid port"),
    ({"name": "web", "ip": "10.0.0.1"}, "invalid port"),
    ({"name": "web", "ip": "10.0.0.1", "port": 70000}, "port out of range"),
    ({"name": "web", "ip": "10.0.0.1", "port": -2}, "port out of range"),
])
def test_put_services_rejects_an_invalid_entry(admin, recorded_sets, entry, expected):
    resp = admin.put("/config/services", json=[entry])
    assert resp.status_code == 400
    assert expected in resp.get_json()["error"]
    assert recorded_sets == []


def test_put_services_normalises_a_valid_payload(admin, recorded_sets):
    """-1 is the sentinel port the seeded 'other' service uses, so it has to
    survive validation."""
    resp = admin.put("/config/services", json=[
        {"name": "  web  ", "ip": " 10.0.0.1 ", "port": "8080", "notes": " main "},
        {"name": "other", "ip": "10.0.0.2", "port": -1},
    ])
    assert resp.status_code == 200
    assert resp.get_json() == [
        {"name": "web", "ip": "10.0.0.1", "port": 8080, "notes": "main"},
        {"name": "other", "ip": "10.0.0.2", "port": -1, "notes": ""},
    ]
    assert dict(recorded_sets)["services"] == resp.get_json()


# --- PUT /config/teams validation ------------------------------------------

def test_put_teams_rejects_a_non_list(admin, recorded_sets):
    resp = admin.put("/config/teams", json={"name": "t1", "ip": "10.0.1.1"})
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "expected a list"
    assert recorded_sets == []


@pytest.mark.parametrize("entry,expected", [
    ("team-one", "team entry must be an object"),
    ({"ip": "10.0.1.1"}, "invalid team name"),
    ({"name": "team!", "ip": "10.0.1.1"}, "invalid team name"),
    ({"name": "team one", "ip": ""}, "team ip is required"),
])
def test_put_teams_rejects_an_invalid_entry(admin, recorded_sets, entry, expected):
    resp = admin.put("/config/teams", json=[entry])
    assert resp.status_code == 400
    assert expected in resp.get_json()["error"]
    assert recorded_sets == []
