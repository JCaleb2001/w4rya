"""Tests for GET /flow/<id>/decode — mirrors the id-validation convention
used by every other flow-id route added alongside it (see
test_routes_attack_incident.py, test_routes_attack_exploit_code.py)."""

from __future__ import annotations

import base64
import datetime
import uuid


class _Item:
    def __init__(self, direction, kind, data):
        self.direction = direction
        self.kind = kind
        self.data = data


class _Flow:
    def __init__(self, items, flow_id=None):
        self.id = flow_id or uuid.UUID("22222222-2222-2222-2222-222222222222")
        self.time = datetime.datetime(2026, 9, 7, tzinfo=datetime.timezone.utc)
        self.items = items


class _FakeConn:
    def __init__(self, flow):
        self._flow = flow

    def flow_detail(self, _fid):
        return self._flow


class _ConnCtx:
    def __init__(self, conn):
        self._conn = conn

    def __enter__(self):
        return self._conn

    def __exit__(self, *a):
        return False


class _FakeDb:
    def __init__(self, flow):
        self._conn = _FakeConn(flow)

    def connection(self):
        return _ConnCtx(self._conn)


def test_flow_decode_invalid_id_is_400(viewer):
    assert viewer.get("/flow/not-a-uuid/decode").status_code == 400


def test_flow_decode_not_found_is_404(monkeypatch, webservice_mod, viewer):
    monkeypatch.setattr(webservice_mod, "db", _FakeDb(None))
    assert viewer.get(f"/flow/{uuid.uuid4()}/decode").status_code == 404


def test_flow_decode_returns_decoded_layers_for_encoded_items(monkeypatch, webservice_mod, app, viewer):
    raw = base64.b64encode(b"whoami")
    flow = _Flow([_Item("c", "raw", raw)])
    monkeypatch.setattr(webservice_mod, "db", _FakeDb(flow))
    resp = viewer.get(f"/flow/{flow.id}/decode")
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["flow_id"] == str(flow.id)
    assert len(body["items"]) == 1
    assert body["items"][0]["item_index"] == 0
