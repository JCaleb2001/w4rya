"""Tests for GET /attack/incident/<flow_id>.

conftest's generic `fake_db` fixture returns `[]` from every Connection
method (including flow_detail), which makes the route 404 before it ever
reaches the classification logic — too shallow to catch a real bug here.
This file fakes a `Flow`-shaped object instead, matching the actual runtime
shape database.flow_detail() hands back: `signatures` is a list of plain
dicts decoded straight off the jsonb column ({"id", "message", "action"}),
never `database.Signature` dataclass instances — attribute access on them
(s.id / s.message) is exactly the bug this file is here to catch a
regression of.
"""

from __future__ import annotations

import datetime
import uuid

import pytest


class _Item:
    def __init__(self, direction, kind, data):
        self.direction = direction
        self.kind = kind
        self.data = data


class _Flow:
    def __init__(self, signatures, items=None, flow_id=None):
        self.id = flow_id or uuid.UUID("11111111-1111-1111-1111-111111111111")
        self.time = datetime.datetime(2026, 9, 7, 12, 0, 0, tzinfo=datetime.timezone.utc)
        self.ip_src = "10.0.0.1"
        self.ip_dst = "10.0.0.2"
        self.port_dst = 8080
        self.signatures = signatures
        self.items = items or [_Item("c", "raw", b"GET / HTTP/1.1\r\n\r\n")]


class _FakeConn:
    def __init__(self, flow, stats):
        self._flow = flow
        self._stats = stats

    def flow_detail(self, _fid):
        return self._flow

    def incident_stats(self, _sid, _src_ip):
        return self._stats


class _ConnCtx:
    def __init__(self, conn):
        self._conn = conn

    def __enter__(self):
        return self._conn

    def __exit__(self, *a):
        return False


class _FakeDb:
    def __init__(self, flow, stats=None):
        self._conn = _FakeConn(flow, stats or {
            "first_seen": "2026-09-01T00:00:00+00:00",
            "last_seen": "2026-09-07T00:00:00+00:00",
            "occurrence_count": 3,
        })

    def connection(self):
        return _ConnCtx(self._conn)


def _install(monkeypatch, webservice_mod, flow, stats=None):
    monkeypatch.setattr(webservice_mod, "db", _FakeDb(flow, stats))


def test_incident_with_dict_signatures_does_not_crash(monkeypatch, webservice_mod, app, viewer):
    """The actual bug: flow.signatures elements are dicts (as psycopg/jsonb
    hands them back), not Signature dataclass instances. Attribute access
    (s.id / s.message) raised AttributeError in production; regression
    guard for that."""
    flow = _Flow(signatures=[
        {"id": 1000009, "message": "Log4Shell JNDI lookup in URI", "action": "allowed"},
    ])
    _install(monkeypatch, webservice_mod, flow)
    client = viewer
    resp = client.get(f"/attack/incident/{flow.id}")
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["sid"] == 1000009
    assert body["technique"].startswith("Exploit Public-Facing Application")
    assert body["occurrence_count"] == 3


def test_incident_picks_highest_severity_when_multiple_signatures(monkeypatch, webservice_mod, app, viewer):
    flow = _Flow(signatures=[
        {"id": 1, "message": "recon tool UA detected", "action": "allowed"},  # low
        {"id": 1000002, "message": "SQLi union select", "action": "allowed"},  # critical
    ])
    _install(monkeypatch, webservice_mod, flow)
    client = viewer
    resp = client.get(f"/attack/incident/{flow.id}")
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["severity"] == "critical"
    assert body["sid"] == 1000002


def test_incident_sid_param_selects_specific_signature(monkeypatch, webservice_mod, app, viewer):
    flow = _Flow(signatures=[
        {"id": 1, "message": "recon tool UA detected", "action": "allowed"},
        {"id": 1000002, "message": "SQLi union select", "action": "allowed"},
    ])
    _install(monkeypatch, webservice_mod, flow)
    client = viewer
    resp = client.get(f"/attack/incident/{flow.id}?sid=1")
    assert resp.status_code == 200
    assert resp.get_json()["sid"] == 1


def test_incident_sid_param_not_on_flow_is_404(monkeypatch, webservice_mod, app, viewer):
    flow = _Flow(signatures=[{"id": 1, "message": "recon tool UA detected", "action": "allowed"}])
    _install(monkeypatch, webservice_mod, flow)
    client = viewer
    resp = client.get(f"/attack/incident/{flow.id}?sid=9999")
    assert resp.status_code == 404


def test_incident_no_signatures_still_returns_a_packet(monkeypatch, webservice_mod, app, viewer):
    """A pure flag-leak flow (no signature hits) is still worth a report."""
    flow = _Flow(signatures=[])
    _install(monkeypatch, webservice_mod, flow, stats=None)
    client = viewer
    resp = client.get(f"/attack/incident/{flow.id}")
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["sid"] is None
    assert body["tactic"] == "Unknown"
    assert "flag leak only" in body["text_packet"]


def test_incident_invalid_flow_id_is_400(app, viewer):
    client = viewer
    resp = client.get("/attack/incident/not-a-uuid")
    assert resp.status_code == 400


def test_incident_flow_not_found_is_404(monkeypatch, webservice_mod, app, viewer):
    _install(monkeypatch, webservice_mod, None)
    client = viewer
    resp = client.get(f"/attack/incident/{uuid.uuid4()}")
    assert resp.status_code == 404


# -- endpoint + vulnerable_inputs (the "tell the patching team what to fix"
# feature) — needs a real rule file on disk so attack.find_exploit_item's
# sid lookup and buffer-scoped matching run for real, same as production.

@pytest.fixture
def rules_files(tmp_path, monkeypatch):
    import attack
    import rules
    custom = tmp_path / "custom.rules"
    et_open = tmp_path / "et-open.rules"
    et_open.write_text("")
    monkeypatch.setattr(rules, "RULES_FILE", str(custom))
    monkeypatch.setattr(attack, "_ET_OPEN_RULES_FILE", str(et_open))
    return custom, et_open


def test_incident_includes_endpoint_and_vulnerable_input_when_isolated(monkeypatch, webservice_mod, rules_files, viewer):
    """The real case this feature exists for: an IDOR via a predictable
    token in a query parameter. The report should name the exact endpoint
    and the exact parameter, not just dump the raw payload."""
    custom, _ = rules_files
    custom.write_text(
        'alert http any any -> any 8008 (msg:"IDOR: /api/sheets accessed via URL token instead '
        'of session cookie"; content:"/api/sheets/"; http_uri; content:"token="; http_uri; sid:1000008;)\n'
    )
    flow = _Flow(
        signatures=[{"id": 1000008, "message": "IDOR: /api/sheets accessed via URL token instead of session cookie", "action": "allowed"}],
        items=[_Item("c", "raw", b"GET /api/sheets/abc123?token=7da31352 HTTP/1.1\r\nHost: x\r\n\r\n")],
    )
    _install(monkeypatch, webservice_mod, flow)
    resp = viewer.get(f"/attack/incident/{flow.id}")
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["endpoint"] == "GET /api/sheets/abc123"
    locations = {v["location"]: v["value"] for v in body["vulnerable_inputs"]}
    assert locations['query parameter "token"'] == "7da31352"
    assert "Endpoint  : GET /api/sheets/abc123" in body["text_packet"]
    assert 'query parameter "token" = "7da31352"' in body["text_packet"]


def test_incident_does_not_confuse_cookie_token_with_query_token(monkeypatch, webservice_mod, rules_files, viewer):
    """Regression guard, at the route level, for the exact Cookie/token
    collision bug found in production: a session-wide auth cookie must
    never be reported as the vulnerable query parameter."""
    custom, _ = rules_files
    custom.write_text(
        'alert http any any -> any 8008 (msg:"IDOR: /api/sheets accessed via URL token instead '
        'of session cookie"; content:"/api/sheets/"; http_uri; content:"token="; http_uri; sid:1000008;)\n'
    )
    flow = _Flow(
        signatures=[{"id": 1000008, "message": "IDOR: /api/sheets accessed via URL token instead of session cookie", "action": "allowed"}],
        items=[
            _Item("c", "raw", b"POST /api/sheets/upload HTTP/1.1\r\nHost: x\r\nCookie: auth-token=deadbeef\r\n\r\n{}"),
            _Item("c", "raw", b"GET /api/sheets/abc123?token=7da31352 HTTP/1.1\r\nHost: x\r\nCookie: auth-token=deadbeef\r\n\r\n"),
        ],
    )
    _install(monkeypatch, webservice_mod, flow)
    resp = viewer.get(f"/attack/incident/{flow.id}")
    body = resp.get_json()
    assert body["endpoint"] == "GET /api/sheets/abc123"  # the real exploit, not the upload
    locations = {v["location"]: v["value"] for v in body["vulnerable_inputs"]}
    assert locations['query parameter "token"'] == "7da31352"
    assert "cookie" not in "".join(locations.keys()).lower()


def test_incident_no_endpoint_or_vulnerable_inputs_when_isolation_fails(monkeypatch, webservice_mod, rules_files, viewer):
    """A rule with no static content to isolate on (pcre-only) must not
    guess at an endpoint/field — better to show nothing than point the
    patching team at the wrong request."""
    custom, _ = rules_files
    custom.write_text('alert http any any -> any any (msg:"x"; pcre:"/foo/"; sid:1000200;)\n')
    flow = _Flow(
        signatures=[{"id": 1000200, "message": "x", "action": "allowed"}],
        items=[
            _Item("c", "raw", b"GET /api/a HTTP/1.1\r\n\r\n"),
            _Item("c", "raw", b"GET /api/b HTTP/1.1\r\n\r\n"),
        ],
    )
    _install(monkeypatch, webservice_mod, flow)
    resp = viewer.get(f"/attack/incident/{flow.id}")
    body = resp.get_json()
    assert body["endpoint"] is None
    assert body["vulnerable_inputs"] == []
    assert "Endpoint" not in body["text_packet"]


def test_incident_matched_items_reports_union_of_endpoints_and_inputs(monkeypatch, webservice_mod, rules_files, viewer):
    """Two genuinely distinct requests both match the rule (not a guess —
    both really did trigger it, see find_exploit_item's "matched_items"
    basis) — the incident packet should report both endpoints and inputs,
    and flag that this was a multi-stage match, instead of reporting only
    the first one and silently dropping the second."""
    custom, _ = rules_files
    custom.write_text(
        'alert http any any -> any any (msg:"x"; content:"/api/"; http.uri; sid:1000200;)\n'
    )
    flow = _Flow(
        signatures=[{"id": 1000200, "message": "x", "action": "allowed"}],
        items=[
            _Item("c", "raw", b"GET /api/a HTTP/1.1\r\n\r\n"),
            _Item("c", "raw", b"GET /api/b HTTP/1.1\r\n\r\n"),
        ],
    )
    _install(monkeypatch, webservice_mod, flow)
    resp = viewer.get(f"/attack/incident/{flow.id}")
    body = resp.get_json()
    assert body["matched_item_count"] == 2
    assert body["endpoint"] == "GET /api/a"  # first match stands as representative
    assert "multi-stage" in body["text_packet"].lower() or "distinct requests" in body["text_packet"].lower()


def test_incident_no_signature_has_no_endpoint(monkeypatch, webservice_mod, rules_files, viewer):
    flow = _Flow(signatures=[])
    _install(monkeypatch, webservice_mod, flow)
    resp = viewer.get(f"/attack/incident/{flow.id}")
    body = resp.get_json()
    assert body["endpoint"] is None
    assert body["vulnerable_inputs"] == []
