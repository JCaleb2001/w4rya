"""Background jobs for the vulnbox page — one at a time, across all workers.

A job runs in a daemon thread of whichever gunicorn worker took the request;
the route returns immediately and the page polls. State lives in `job.json`
(atomic writes) so every worker — and therefore every poll — sees the same
thing: the current job plus the last result of each kind, so running recon
doesn't wipe the backup card.

An exclusive flock on `job.lock` is held for the job's whole life:

- `start()` takes it non-blocking, so a second start while one runs raises
  `JobBusy` (→ 409) instead of two jobs hammering the box at once.
- `snapshot()` probes it: a record that says "running" while nobody holds the
  lock means the worker died mid-job (restart, OOM). That is reported as
  interrupted — decided exactly by the lock, not guessed from timestamps.
  flock locks belong to the open file description, so the probe is correct
  within one process as well as across workers.
"""

from __future__ import annotations

import fcntl
import json
import os
import tempfile
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Callable

from . import config

KINDS = ("preflight", "recon", "backup")


class JobBusy(Exception):
    """A job is already running; `kind` says which."""

    def __init__(self, kind: str):
        super().__init__(f"a {kind} job is already running")
        self.kind = kind


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _empty() -> dict:
    return {"current": None, "last": {}}


def _read(path=None) -> dict:
    try:
        with open(path or config.job_path()) as f:
            state = json.load(f)
    except (OSError, ValueError):
        return _empty()
    if not isinstance(state, dict):
        return _empty()
    state.setdefault("current", None)
    state.setdefault("last", {})
    return state


def _write(state: dict, path=None) -> None:
    """Atomic replace + hand the file to the data dir's owner (the api runs as
    root over a host bind mount — same rule as user_store._write_atomic)."""
    path = path or config.job_path()
    config.ensure_dir(path.parent)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".job.", suffix=".json")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(state, f)
        os.chmod(tmp, 0o644)
        try:
            st = path.parent.stat()
            os.chown(tmp, st.st_uid, st.st_gid)
        except OSError:
            pass
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _open_lock() -> int:
    path = config.job_lock_path()
    config.ensure_dir(path.parent)
    existed = path.exists()
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    if not existed:
        try:
            st = path.parent.stat()
            os.chown(path, st.st_uid, st.st_gid)
        except OSError:
            pass
    return fd


def _try_lock(fd: int) -> bool:
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except BlockingIOError:
        return False


def start(kind: str, fn: Callable[[], dict], *, actor: str) -> dict:
    """Run `fn` in the background. Raises JobBusy if a job is running."""
    if kind not in KINDS:
        raise ValueError(f"unknown job kind: {kind!r}")
    fd = _open_lock()
    # One short retry: snapshot() holds the lock for a few microseconds while
    # it reconciles a finished/dead job, which must not read as "busy".
    if not _try_lock(fd):
        time.sleep(0.05)
        if not _try_lock(fd):
            os.close(fd)
            running = (_read().get("current") or {}).get("kind") or "vulnbox"
            raise JobBusy(running)

    # Pin the state file for the job's whole life: a job always reports back
    # to the job.json it started from.
    path = config.job_path()
    record = {
        "id": uuid.uuid4().hex, "kind": kind, "state": "running",
        "started_by": actor, "started_at": _now(), "finished_at": None,
        "result": None, "error": None,
    }
    try:
        state = _read(path)
        state["current"] = record
        _write(state, path)
    except Exception:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
        raise
    threading.Thread(target=_work, args=(fd, path, dict(record), fn), daemon=True).start()
    return record


def _work(fd: int, path, record: dict, fn: Callable[[], dict]) -> None:
    try:
        record["result"] = fn()
        record["state"] = "done"
    except Exception as e:  # report every failure; never let the thread die silently
        record["state"] = "error"
        record["error"] = str(e) or e.__class__.__name__
    finally:
        record["finished_at"] = _now()
        try:
            state = _read(path)
            state["current"] = record
            state["last"][record["kind"]] = record
            _write(state, path)
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)


def snapshot() -> dict:
    """Current job + last result per kind, with dead jobs marked interrupted."""
    state = _read()
    cur = state.get("current")
    if not (cur and cur.get("state") == "running"):
        return state
    fd = _open_lock()
    try:
        if not _try_lock(fd):
            return state  # genuinely running
        try:
            # Re-read under the lock: the job may have finished between our
            # first read and the probe, and its "done" must not be clobbered.
            state = _read()
            cur = state.get("current")
            if cur and cur.get("state") == "running":
                cur["state"] = "error"
                cur["error"] = "interrupted — the api restarted while this job was running"
                cur["finished_at"] = _now()
                state["last"][cur["kind"]] = cur
                _write(state)
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
        return state
    finally:
        os.close(fd)
