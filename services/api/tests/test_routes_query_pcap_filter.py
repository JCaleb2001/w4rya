"""Tests for POST /query's pcap_name filter — lets the sidebar find flows
from a pcap whose own capture timestamp falls way outside the game's
tick-0 anchor (a historical/test pcap loaded for detection testing), which
the tick/time filter alone can never surface without already knowing that
offset. conftest's generic `fake_db` always returns `[]` from `flow_query`
regardless of the query built, so it can't catch a regression here — this
file fakes a `Connection` that RECORDS the `database.FlowQuery` it was
called with instead.
"""

from __future__ import annotations


class _RecordingConn:
    def __init__(self):
        self.last_query = None

    def flow_query(self, query):
        self.last_query = query
        return []

    def tag_list(self):
        return []


class _ConnCtx:
    def __init__(self, conn):
        self._conn = conn

    def __enter__(self):
        return self._conn

    def __exit__(self, *a):
        return False


class _RecordingDb:
    def __init__(self):
        self.conn = _RecordingConn()

    def connection(self):
        return _ConnCtx(self.conn)


def _install(monkeypatch, webservice_mod):
    db = _RecordingDb()
    monkeypatch.setattr(webservice_mod, "db", db)
    return db


def test_query_passes_pcap_name_through_to_flow_query(monkeypatch, webservice_mod, viewer):
    db = _install(monkeypatch, webservice_mod)
    resp = viewer.post("/query", json={"pcap_name": "fastjson"})
    assert resp.status_code == 200
    assert db.conn.last_query.pcap_name == "fastjson"


def test_query_strips_whitespace_from_pcap_name(monkeypatch, webservice_mod, viewer):
    db = _install(monkeypatch, webservice_mod)
    viewer.post("/query", json={"pcap_name": "  fastjson  "})
    assert db.conn.last_query.pcap_name == "fastjson"


def test_query_blank_pcap_name_is_none(monkeypatch, webservice_mod, viewer):
    db = _install(monkeypatch, webservice_mod)
    viewer.post("/query", json={"pcap_name": "   "})
    assert db.conn.last_query.pcap_name is None


def test_query_missing_pcap_name_defaults_to_none(monkeypatch, webservice_mod, viewer):
    db = _install(monkeypatch, webservice_mod)
    viewer.post("/query", json={})
    assert db.conn.last_query.pcap_name is None


def test_query_pcap_name_coexists_with_other_filters(monkeypatch, webservice_mod, viewer):
    """The backend itself doesn't force pcap_name and time_from/time_to to
    be mutually exclusive — that's a frontend UX choice (FlowList.tsx drops
    the time filter client-side when a pcap filter is active). The backend
    stays flexible and just passes through whatever was given."""
    db = _install(monkeypatch, webservice_mod)
    viewer.post("/query", json={
        "pcap_name": "fastjson", "time_from": "2021-01-01T00:00:00Z",
    })
    assert db.conn.last_query.pcap_name == "fastjson"
    assert db.conn.last_query.time_from is not None
