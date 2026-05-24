"""Per-flow notes — quick team-coordination scratch pad.

Schema lives alongside the rest of the runtime tables in Timescale. We don't
hot-cache notes (they're small and write-heavy enough that caching would just
introduce staleness); each request hits the DB directly.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Optional


_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS flow_notes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    flow_id UUID NOT NULL,
    author TEXT NOT NULL,
    body TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS flow_notes_flow_id_idx
    ON flow_notes(flow_id, created_at DESC);
"""


@dataclass
class Note:
    id: uuid.UUID
    flow_id: uuid.UUID
    author: str
    body: str
    created_at: datetime

    def to_dict(self) -> dict:
        return {
            "id": str(self.id),
            "flow_id": str(self.flow_id),
            "author": self.author,
            "body": self.body,
            "created_at": self.created_at.isoformat(),
        }


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


def list_for_flow(flow_id: uuid.UUID) -> list[Note]:
    if _pool is None:
        return []
    with _pool.connection() as conn:
        cur = conn.execute(
            "SELECT id, flow_id, author, body, created_at "
            "FROM flow_notes WHERE flow_id = %s ORDER BY created_at ASC",
            (flow_id,),
        )
        return [
            Note(id=r[0], flow_id=r[1], author=r[2], body=r[3], created_at=r[4])
            for r in cur.fetchall()
        ]


def add(flow_id: uuid.UUID, author: str, body: str) -> Note:
    if _pool is None:
        raise RuntimeError("notes: pool not initialized")
    body = body.strip()
    if not body:
        raise ValueError("body cannot be empty")
    if len(body) > 10_000:
        raise ValueError("note too long (max 10000 chars)")
    with _pool.connection() as conn:
        cur = conn.execute(
            "INSERT INTO flow_notes (flow_id, author, body) "
            "VALUES (%s, %s, %s) RETURNING id, flow_id, author, body, created_at",
            (flow_id, author, body),
        )
        row = cur.fetchone()
        conn.commit()
    return Note(id=row[0], flow_id=row[1], author=row[2], body=row[3], created_at=row[4])


def delete(note_id: uuid.UUID, requester: str) -> Optional[str]:
    """Delete a note. Only the original author may delete.

    Returns None on success, or an error string ('not_found' / 'forbidden').
    """
    if _pool is None:
        return "internal"
    with _pool.connection() as conn:
        cur = conn.execute(
            "SELECT author FROM flow_notes WHERE id = %s", (note_id,)
        )
        row = cur.fetchone()
        if not row:
            return "not_found"
        if row[0] != requester:
            return "forbidden"
        conn.execute("DELETE FROM flow_notes WHERE id = %s", (note_id,))
        conn.commit()
    return None
