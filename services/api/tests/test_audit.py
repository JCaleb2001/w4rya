"""Tests for audit.py — the append-only audit log.

audit.py talks to its own module-level `_pool` (set via `set_pool()` at app
boot), separate from `webservice_mod.db` / conftest's FakeDb. Nothing in the
existing suite ever calls `set_pool`, so `_pool` stays None and every one of
these code paths — the SQL/param building in recent(), the actor-default and
Jsonb-vs-None branching in log(), the swallow-all-exceptions contract — was
previously untested. These tests fake `_pool` with a small recording stand-in
so the query-building logic gets exercised without a live database.
"""

from __future__ import annotations

import datetime

import pytest


class _RecordingCursor:
    def __init__(self, rows):
        self._rows = rows

    def fetchall(self):
        return self._rows


class _RecordingConn:
    def __init__(self, rows, calls):
        self._rows = rows
        self._calls = calls

    def execute(self, sql, params=None):
        self._calls.append((sql, params))
        return _RecordingCursor(self._rows)

    def commit(self):
        pass


class _ConnCtx:
    def __init__(self, pool):
        self._pool = pool

    def __enter__(self):
        return _RecordingConn(self._pool.rows, self._pool.calls)

    def __exit__(self, *a):
        return False


class _RecordingPool:
    def __init__(self, rows=None):
        self.rows = rows if rows is not None else []
        self.calls = []

    def connection(self):
        return _ConnCtx(self)


class _RaisingPool:
    """Simulates a dead/unreachable database: entering the connection
    context itself raises, before any query is built."""

    def connection(self):
        class _Ctx:
            def __enter__(self):
                raise OSError("connection refused")

            def __exit__(self, *a):
                return False

        return _Ctx()


@pytest.fixture(autouse=True)
def _reset_pool():
    """audit._pool is module-global state; without this a pool set by one
    test would leak into the next (conftest's users_file fixture pattern)."""
    import audit
    audit._pool = None
    yield
    audit._pool = None


# -- log() --------------------------------------------------------------------

def test_log_noop_when_pool_unset():
    import audit
    # Should not raise even though nothing is configured.
    audit.log("alice", "rules.add", target="42")


def test_log_writes_expected_sql_and_params():
    import audit
    pool = _RecordingPool()
    audit._pool = pool
    audit.log("alice", "rules.add", target="42", details={"k": "v"})
    assert len(pool.calls) == 1
    sql, params = pool.calls[0]
    assert "INSERT INTO audit_log" in sql
    actor, action, target, details = params
    assert (actor, action, target) == ("alice", "rules.add", "42")
    assert details.obj == {"k": "v"}  # Jsonb wrapper


def test_log_defaults_falsy_actor_to_anon():
    import audit
    pool = _RecordingPool()
    audit._pool = pool
    audit.log("", "login_fail")
    _, params = pool.calls[0]
    assert params[0] == "anon"


def test_log_details_none_stays_none_not_jsonb():
    import audit
    pool = _RecordingPool()
    audit._pool = pool
    audit.log("alice", "logout")
    _, params = pool.calls[0]
    assert params[3] is None


def test_log_swallows_exceptions_from_dead_pool():
    import audit
    audit._pool = _RaisingPool()
    # The whole point of "fire-and-forget": a broken audit backend must never
    # surface to the caller (a write endpoint mid-request).
    audit.log("alice", "rules.add")


def test_log_swallows_exceptions_and_logs_a_warning(caplog):
    import audit
    audit._pool = _RaisingPool()
    with caplog.at_level("WARNING", logger="audit"):
        audit.log("alice", "rules.add")
    assert any("audit.log failed" in r.message for r in caplog.records)


# -- recent() -------------------------------------------------------------

def _row(actor="alice", action="rules.add", target="42", details=None):
    return (
        "00000000-0000-0000-0000-000000000001",
        datetime.datetime(2026, 9, 5, 12, 0, 0, tzinfo=datetime.timezone.utc),
        actor,
        action,
        target,
        details,
    )


def test_recent_no_pool_returns_empty_list():
    import audit
    assert audit.recent() == []


def test_recent_maps_rows_to_dicts():
    import audit
    pool = _RecordingPool(rows=[_row()])
    audit._pool = pool
    out = audit.recent()
    assert out == [{
        "id": "00000000-0000-0000-0000-000000000001",
        "when": "2026-09-05T12:00:00+00:00",
        "actor": "alice",
        "action": "rules.add",
        "target": "42",
        "details": None,
    }]


def test_recent_builds_where_clause_for_all_filters():
    import audit
    pool = _RecordingPool(rows=[])
    audit._pool = pool
    after = datetime.datetime(2026, 9, 5, tzinfo=datetime.timezone.utc)
    audit.recent(limit=50, after_ts=after, actor="bob", action_prefix="rules.")
    sql, params = pool.calls[0]
    assert "when_ts > %s" in sql
    assert "actor = %s" in sql
    assert "action LIKE %s" in sql
    # Params are appended in the order the clauses are built: after_ts, actor,
    # action_prefix (with trailing wildcard), then limit last.
    assert params == [after, "bob", "rules.%", 50]


def test_recent_action_prefix_strips_literal_percent():
    """A caller-supplied '%' in action_prefix is stripped before the
    trailing wildcard is appended, so it can't widen the match beyond a
    prefix search."""
    import audit
    pool = _RecordingPool(rows=[])
    audit._pool = pool
    audit.recent(action_prefix="rul%es")
    _, params = pool.calls[0]
    assert params[-2] == "rules%"


def test_recent_no_filters_has_no_where_clause():
    import audit
    pool = _RecordingPool(rows=[])
    audit._pool = pool
    audit.recent(limit=10)
    sql, params = pool.calls[0]
    assert "WHERE" not in sql
    assert params == [10]


# -- distinct_actors() ------------------------------------------------------

def test_distinct_actors_no_pool_returns_empty_list():
    import audit
    assert audit.distinct_actors() == []


def test_distinct_actors_maps_single_column_rows():
    import audit
    pool = _RecordingPool(rows=[("alice",), ("bob",)])
    audit._pool = pool
    assert audit.distinct_actors() == ["alice", "bob"]


# -- init_schema() / set_pool() ----------------------------------------------

def test_init_schema_noop_without_pool():
    import audit
    audit.init_schema()  # must not raise


def test_init_schema_executes_and_commits_with_pool():
    import audit
    pool = _RecordingPool()
    audit._pool = pool
    audit.init_schema()
    assert len(pool.calls) == 1
    sql, params = pool.calls[0]
    assert "CREATE TABLE IF NOT EXISTS audit_log" in sql


def test_set_pool_installs_the_module_global():
    import audit
    pool = _RecordingPool()
    audit.set_pool(pool)
    assert audit._pool is pool
