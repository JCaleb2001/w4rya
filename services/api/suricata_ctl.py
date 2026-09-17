"""Talk to Suricata's unix command socket — the lightweight way to trigger
`reload-rules` without docker.sock access or PID-namespace sharing.

Suricata exposes a newline-framed JSON protocol on the command socket when
started with `--set unix-command.enabled=yes`. The protocol is a one-line
handshake (`{"version": "0.2"}`) followed by single-command messages.

If the socket isn't present (suricata not running, wrong mount, etc.) we
raise FileNotFoundError so the api can 503 cleanly.
"""

from __future__ import annotations

import json
import os
import socket as _socket
import time as _time
from typing import Any

import rules as _rules

try:
    import fcntl  # POSIX only — the api container always runs on Linux;
    # a Windows dev/test environment (no fcntl) falls back to unlocked
    # reload_rules() below, which is fine there since it has no real
    # Suricata socket to coordinate access to anyway.
except ImportError:
    fcntl = None

SOCKET_PATH = os.environ.get(
    "W4RYA_SURICATA_SOCKET", "/var/run/suricata/suricata-command.socket"
)
# Cross-process coordination for reload_rules() — see its docstring. All
# gunicorn workers share the same container filesystem, so a plain file
# lock (not a threading.Lock, which wouldn't cross worker *processes*) is
# enough.
_RELOAD_LOCK_PATH = os.environ.get(
    "W4RYA_SURICATA_RELOAD_LOCK", "/tmp/w4rya-suricata-reload.lock"
)
_RELOAD_STATE_PATH = os.environ.get(
    "W4RYA_SURICATA_RELOAD_STATE", "/tmp/w4rya-suricata-reload.state"
)
# `reload-rules` has to recompile the whole multi-pattern matcher, so its
# cost scales with ruleset size, not request size — 1.5s (fine for `uptime`,
# a handful of custom rules) was found to always time out once the ET Open
# set is loaded: a real reload against ~40k active rules took ~8.5s wall
# clock (Suricata's own log confirmed "rule reload complete" well after the
# client had already given up and closed the socket, which Suricata then
# logged as a broken pipe trying to write the response). 20s leaves
# headroom for slower hardware/an even larger ruleset while staying well
# under gunicorn's 60s worker timeout.
DEFAULT_TIMEOUT = 20.0


def _read_line(sock: _socket.socket) -> bytes:
    """Read a single newline-terminated message off the socket."""
    buf = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
        if b"\n" in buf:
            break
    line, _, _ = buf.partition(b"\n")
    return line


def _send_command(cmd: dict, timeout: float = DEFAULT_TIMEOUT) -> dict:
    if not os.path.exists(SOCKET_PATH):
        raise FileNotFoundError(
            f"suricata command socket not present at {SOCKET_PATH} "
            "(is suricata running with --set unix-command.enabled=yes?)"
        )
    sock = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect(SOCKET_PATH)
        # handshake
        sock.sendall((json.dumps({"version": "0.2"}) + "\n").encode())
        hs_raw = _read_line(sock)
        if not hs_raw:
            raise OSError("suricata closed the connection during handshake")
        hs = json.loads(hs_raw)
        if hs.get("return") != "OK":
            raise OSError(f"suricata rejected handshake: {hs}")
        # command
        sock.sendall((json.dumps(cmd) + "\n").encode())
        resp_raw = _read_line(sock)
        if not resp_raw:
            raise OSError("suricata closed the connection before responding")
        return json.loads(resp_raw)
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _read_reload_state() -> dict:
    try:
        with open(_RELOAD_STATE_PATH, "r") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _write_reload_state(state: dict) -> None:
    tmp = f"{_RELOAD_STATE_PATH}.tmp"
    with open(tmp, "w") as f:
        json.dump(state, f)
    os.replace(tmp, _RELOAD_STATE_PATH)


def _rules_file_version() -> int | None:
    """Fingerprint of the on-disk rules file, used to decide whether a
    completed reload actually covers a given caller's edit (see
    reload_rules docstring). None if the file doesn't exist yet."""
    try:
        return os.stat(_rules.RULES_FILE).st_mtime_ns
    except OSError:
        return None


def reload_rules(blocking: bool = True) -> dict:
    """Ask Suricata to re-read the rules file. Returns the raw response dict.

    Coalesces concurrent callers: a reload against a large ruleset (~40k
    active ET Open rules) can take several seconds, and several gunicorn
    workers — separate OS processes, so an in-process threading.Lock
    wouldn't help — can each try to trigger one within the same few
    seconds (e.g. two operators saving rule edits back to back). A file
    lock (shared by all workers via the container's filesystem) serializes
    the actual socket calls.

    Coalescing is decided by comparing the rules file's mtime, not by
    wall-clock arrival order: a caller only reuses another reload's result
    if that reload's own snapshot of the file (taken right before it sent
    reload-rules to Suricata) matches the file's current mtime. Wall-clock
    "did I start waiting after that other reload began" doesn't guarantee
    the other reload's socket call actually happened after this caller's
    own edit hit disk, and coalescing into a stale reload would silently
    drop a rule change.

    `blocking=True` (the manual "reload now" button, POST /rules/reload) is
    a deliberate, infrequent action — it waits for the real result. The
    high-frequency auto-reload-on-save path (`_maybe_autoreload` in
    webservice.py, on every add/update/delete/block-ip) uses
    `blocking=False`: with only 3 sync gunicorn workers, having every one
    of them block up to DEFAULT_TIMEOUT seconds inside the request handler
    while one of them actually talks to Suricata can tie up the whole pool.
    A non-blocking caller that loses the race for the lock returns
    immediately with a "PENDING" status instead of waiting — a background
    thread/polling endpoint would avoid this more thoroughly, but adds
    real complexity (lifecycle outside the request, a new endpoint, poll
    logic in the frontend) that isn't worth it for this traffic profile
    (bursty rule edits, not sustained concurrency). The always-available
    manual reload button is the mitigation for the residual case where an
    operator's last edit lands with nothing left to trigger another
    reload.
    """
    if fcntl is None:
        return _send_command({"command": "reload-rules"})
    lock_fd = os.open(_RELOAD_LOCK_PATH, os.O_CREAT | os.O_RDWR, 0o666)
    try:
        if blocking:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
        else:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return {"return": "PENDING", "message": "reload already in progress"}
        current_version = _rules_file_version()
        state = _read_reload_state()
        if current_version is not None and state.get("reloaded_version") == current_version:
            return state.get("result", {"return": "OK", "message": "coalesced"})
        version_before_send = _rules_file_version()
        result = _send_command({"command": "reload-rules"})
        _write_reload_state({"reloaded_version": version_before_send, "result": result})
        return result
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


def uptime() -> dict:
    """Health check — also confirms the socket protocol is reachable."""
    return _send_command({"command": "uptime"})


def available() -> bool:
    """True iff Suricata is reachable right now (used by the UI to grey out
    the reload button when there's no point)."""
    return os.path.exists(SOCKET_PATH)
