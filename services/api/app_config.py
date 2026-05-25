"""Runtime-editable configuration for the w4rya api.

Backed by an `app_config` table in Timescale. The UI's /config endpoints
write here; route handlers read via `get(key)` (5-second TTL cache).

The pool is injected at startup by webservice.py via `set_pool()`. We don't
import `database` here to avoid the obvious circular dependency.

Defaults come from env vars at import time (mirroring the old
configurations.py behavior). Used only as fallback when the DB has no row
for a given key — once the user PUTs a value, the DB wins forever.
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
from typing import Any, Optional

from psycopg.types.json import Jsonb

_TTL = 5.0
_lock = threading.RLock()
_cache: dict[str, tuple[float, Any]] = {}
_pool = None  # set via set_pool()


# Defaults — mirror the old hardcoded values in configurations.py so a fresh
# install behaves identically until the user edits anything via the UI.
_HELPER = """
10.61.5.1:1237 CyberUni 4
10.61.5.1:1236 CyberUni 3
10.61.5.1:1235 CyberUni 1
10.61.5.1:1234 CyberUni 2
10.60.5.1:3003 ClosedSea 1
10.60.5.1:3004 ClosedSea 2
10.62.5.1:5000 Trademark
10.63.5.1:1337 RPN
""".strip()


def _seed_services() -> list[dict]:
    out: list[dict] = []
    for line in _HELPER.splitlines():
        parts = line.split(" ", 1)
        ip_port = parts[0]
        name = parts[1] if len(parts) > 1 else "service"
        ip, _, port = ip_port.partition(":")
        try:
            out.append({"name": name, "ip": ip, "port": int(port), "notes": ""})
        except ValueError:
            continue
    out.append({"name": "other", "ip": "10.60.2.1", "port": -1, "notes": ""})
    return out


DEFAULTS: dict[str, Any] = {
    "services": _seed_services(),
    "teams": [],
    "flag_regex": os.environ.get("FLAG_REGEX", "[A-Z0-9]{31}="),
    "tick_length": int(os.environ.get("TICK_LENGTH") or 180000),
    "start_date": os.environ.get("TICK_START", "2024-11-30T13:00:00Z"),
    "flag_lifetime": int(os.environ.get("FLAG_LIFETIME") or 5),
    "vm_ip": os.environ.get("VM_IP", "10.10.3.1"),
    "team_id": os.environ.get("TEAM_ID", "0"),
    "visualizer_url": os.environ.get("VISUALIZER_URL", ""),
    "bpf": os.environ.get("BPF", ""),
    # B1: trigger suricatasc reload-rules after every rules CRUD when on
    "rules_autoreload": False,
}


_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS app_config (
    key TEXT PRIMARY KEY,
    value JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)
"""


def set_pool(pool) -> None:
    """Wire the database pool. Called once at startup."""
    global _pool
    _pool = pool


def init_schema() -> None:
    """Ensure the app_config table exists. Safe to call repeatedly."""
    if _pool is None:
        return
    with _pool.connection() as conn:
        conn.execute(_SCHEMA_SQL)
        conn.commit()


def _read_db(key: str) -> Optional[Any]:
    if _pool is None:
        return None
    try:
        with _pool.connection() as conn:
            cur = conn.execute("SELECT value FROM app_config WHERE key = %s", (key,))
            row = cur.fetchone()
            return row[0] if row else None
    except Exception:
        return None


def get(key: str, default: Any = None) -> Any:
    """Return the current value for `key`. Order: cache → DB → DEFAULTS → default."""
    now = time.time()
    with _lock:
        cached = _cache.get(key)
        if cached and (now - cached[0]) < _TTL:
            return cached[1]

    val = _read_db(key)
    if val is None:
        val = DEFAULTS.get(key, default)

    with _lock:
        _cache[key] = (now, val)
    return val


def get_fresh(key: str, default: Any = None) -> Any:
    """Bypass the per-worker cache. Use when you need to see a value just
    written by another gunicorn worker (e.g. a feature toggle that must
    take effect across workers immediately)."""
    val = _read_db(key)
    if val is None:
        val = DEFAULTS.get(key, default)
    with _lock:
        _cache[key] = (time.time(), val)
    return val


def set(key: str, value: Any) -> None:
    """Persist `value` and invalidate the cache for this key."""
    if _pool is None:
        raise RuntimeError("app_config: pool not initialized")
    with _pool.connection() as conn:
        conn.execute(
            "INSERT INTO app_config (key, value) VALUES (%s, %s) "
            "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()",
            (key, Jsonb(value)),
        )
        conn.commit()
    with _lock:
        _cache[key] = (time.time(), value)


def invalidate(key: Optional[str] = None) -> None:
    """Drop the cache (for one key or all)."""
    with _lock:
        if key is None:
            _cache.clear()
        else:
            _cache.pop(key, None)


# --- Validators used by the PUT endpoints ----------------------------------

_NAME_RE = re.compile(r"^[A-Za-z0-9 _\-./]{1,64}$")


def validate_service(entry: Any) -> dict:
    if not isinstance(entry, dict):
        raise ValueError("service entry must be an object")
    name = str(entry.get("name", "")).strip()
    ip = str(entry.get("ip", "")).strip()
    port = entry.get("port")
    notes = str(entry.get("notes", "")).strip()
    if not _NAME_RE.match(name):
        raise ValueError(f"invalid service name: {name!r}")
    if not ip:
        raise ValueError("service ip is required")
    try:
        port = int(port)
    except (TypeError, ValueError):
        raise ValueError(f"invalid port: {port!r}")
    if port < -1 or port > 65535:
        raise ValueError(f"port out of range: {port}")
    return {"name": name, "ip": ip, "port": port, "notes": notes}


def validate_team(entry: Any) -> dict:
    if not isinstance(entry, dict):
        raise ValueError("team entry must be an object")
    name = str(entry.get("name", "")).strip()
    ip = str(entry.get("ip", "")).strip()
    notes = str(entry.get("notes", "")).strip()
    if not _NAME_RE.match(name):
        raise ValueError(f"invalid team name: {name!r}")
    if not ip:
        raise ValueError("team ip is required")
    return {"name": name, "ip": ip, "notes": notes}


# Allowed scalar config keys editable via PUT /config (the wide game form).
SCALAR_KEYS = {
    "flag_regex",
    "tick_length",
    "start_date",
    "flag_lifetime",
    "vm_ip",
    "team_id",
    "visualizer_url",
    "bpf",
    "rules_autoreload",
}

BOOL_KEYS = {"rules_autoreload"}


_REDOS_HINT = re.compile(r"\([^)]*[+*][^)]*\)[+*]")


def coerce_scalar(key: str, raw: Any) -> Any:
    if key == "tick_length" or key == "flag_lifetime":
        return int(raw)
    if key in BOOL_KEYS:
        if isinstance(raw, bool):
            return raw
        if isinstance(raw, (int, float)):
            return bool(raw)
        if isinstance(raw, str):
            return raw.strip().lower() in ("true", "1", "yes", "on")
        return False
    if key == "flag_regex":
        s = str(raw)
        # D1: validate at write-time so a typo doesn't break /query for the
        # whole team later.
        try:
            re.compile(s)
        except re.error as e:
            raise ValueError(f"invalid regex: {e}")
        # Cheap ReDoS heuristic: nested unbounded quantifiers like
        # (foo+)+ or (.*x.*)*. We reject these to keep the team safe from
        # an accidental catastrophic-backtracking pattern that would freeze
        # every /query request.
        if _REDOS_HINT.search(s):
            raise ValueError(
                "regex has nested unbounded quantifiers (likely ReDoS-prone); "
                "please simplify"
            )
        return s
    return str(raw)
