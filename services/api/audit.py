"""Append-only audit log of authenticated state-changing actions.

Hooks live in webservice.py — every write endpoint posts an entry here.
Reads come back through GET /audit (admin-only).

Fire-and-forget: a failure to log never propagates to the caller.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Optional

from psycopg.types.json import Jsonb

_log = logging.getLogger(__name__)

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    when_ts TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT,
    details JSONB
);
CREATE INDEX IF NOT EXISTS audit_log_when_idx ON audit_log(when_ts DESC);
"""

_pool = None


def set_pool(pool) -> None:
    global _pool
    _pool = pool


def init_schema() -> None:
    if _pool is None:
        return
    with _pool.connection() as conn:
        conn.execute(_SCHEMA_SQL)
        conn.commit()


def log(
    actor: str,
    action: str,
    target: Optional[str] = None,
    details: Optional[dict] = None,
) -> None:
    """Fire-and-forget. Swallows all errors — audit failures should never
    break user-facing actions."""
    if _pool is None:
        return
    try:
        with _pool.connection() as conn:
            conn.execute(
                "INSERT INTO audit_log (actor, action, target, details) "
                "VALUES (%s, %s, %s, %s)",
                (
                    actor or "anon",
                    action,
                    target,
                    Jsonb(details) if details is not None else None,
                ),
            )
            conn.commit()
    except Exception as e:
        _log.warning("audit.log failed: %s", e)


def recent(
    limit: int = 200,
    after_ts: Optional[datetime] = None,
    actor: Optional[str] = None,
    action_prefix: Optional[str] = None,
) -> list[dict]:
    if _pool is None:
        return []
    clauses = []
    params: list[Any] = []
    if after_ts is not None:
        clauses.append("when_ts > %s")
        params.append(after_ts)
    if actor:
        clauses.append("actor = %s")
        params.append(actor)
    if action_prefix:
        clauses.append("action LIKE %s")
        # Wildcard at end only — prefix match (e.g. 'rules.' → rules.add,
        # rules.update, rules.delete). LIKE escapes left to defaults.
        params.append(action_prefix.replace("%", "") + "%")
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    sql = (
        "SELECT id, when_ts, actor, action, target, details "
        "FROM audit_log" + where + " ORDER BY when_ts DESC LIMIT %s"
    )
    params.append(int(limit))
    out: list[dict] = []
    with _pool.connection() as conn:
        cur = conn.execute(sql, params)
        for row in cur.fetchall():
            out.append({
                "id": str(row[0]),
                "when": row[1].isoformat(),
                "actor": row[2],
                "action": row[3],
                "target": row[4],
                "details": row[5],
            })
    return out


def distinct_actors(limit: int = 100) -> list[str]:
    if _pool is None:
        return []
    with _pool.connection() as conn:
        cur = conn.execute(
            "SELECT DISTINCT actor FROM audit_log ORDER BY actor LIMIT %s",
            (int(limit),),
        )
        return [r[0] for r in cur.fetchall()]
