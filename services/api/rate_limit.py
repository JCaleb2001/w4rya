"""In-memory rate limiter for the API.

Per-key sliding window: store timestamps of recent failures, drop expired
ones on read, refuse if the bucket is full.

This is per-gunicorn-worker — with N workers an attacker effectively gets
N * MAX_ATTEMPTS attempts before lockout. For team-internal threat model
that's acceptable (still way better than unlimited). For a public-facing
deployment, swap this for a Redis-backed counter.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque

# Defaults tuned for /login. Importers can pass custom limits.
LOGIN_WINDOW_SEC = 300       # 5 minutes
LOGIN_MAX_FAILS = 5

# /setup is public and creates the first admin, so it gets its own bucket:
# keyed by IP only (there is no username to key on yet) and tighter, since a
# legitimate installer needs one or two attempts, not five.
SETUP_WINDOW_SEC = 600       # 10 minutes
SETUP_MAX_FAILS = 3

_lock = threading.Lock()
_failures: dict[str, deque[float]] = defaultdict(deque)


def _prune_locked(key: str, window: float) -> deque[float]:
    now = time.monotonic()
    q = _failures[key]
    while q and q[0] < now - window:
        q.popleft()
    return q


def is_blocked(key: str, *, window: float = LOGIN_WINDOW_SEC,
               max_fails: int = LOGIN_MAX_FAILS) -> bool:
    """True if the key has hit the failure ceiling within `window` seconds."""
    with _lock:
        q = _prune_locked(key, window)
        return len(q) >= max_fails


def record_failure(key: str, *, window: float = LOGIN_WINDOW_SEC) -> int:
    """Record a failure timestamp. Returns current count in window."""
    with _lock:
        q = _prune_locked(key, window)
        q.append(time.monotonic())
        return len(q)


def clear(key: str) -> None:
    """Drop all recorded failures for a key (call on successful auth)."""
    with _lock:
        _failures.pop(key, None)


def seconds_until_unblock(key: str, *, window: float = LOGIN_WINDOW_SEC,
                          max_fails: int = LOGIN_MAX_FAILS) -> int:
    """How many seconds until the next attempt is allowed (rough)."""
    with _lock:
        q = _failures.get(key) or deque()
        if len(q) < max_fails:
            return 0
        # When the oldest failure ages out, the bucket has room again.
        return max(0, int(q[0] + window - time.monotonic()))
