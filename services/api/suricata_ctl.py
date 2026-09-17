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


def reload_rules() -> dict:
    """Ask Suricata to re-read the rules file. Returns the raw response dict.

    Coalesces concurrent callers: a reload against a large ruleset (~40k
    active ET Open rules) can take several seconds, and several gunicorn
    workers — separate OS processes, so an in-process threading.Lock
    wouldn't help — can each try to trigger one within the same few
    seconds (e.g. two operators saving rule edits back to back). Left
    uncoordinated, every worker independently blocks on its own socket
    call, which with only a handful of sync workers can occupy the whole
    pool. A file lock (shared by all workers via the container's
    filesystem) serializes the actual socket calls; a caller that starts
    waiting for the lock AFTER another reload already began skips
    triggering a second one and reuses that one's result instead, since a
    reload that completed after this call started already covers whatever
    rule state prompted it.
    """
    if fcntl is None:
        return _send_command({"command": "reload-rules"})
    requested_at = _time.time()
    lock_fd = os.open(_RELOAD_LOCK_PATH, os.O_CREAT | os.O_RDWR, 0o666)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        state = _read_reload_state()
        if state.get("completed_at", 0) >= requested_at:
            return state.get("result", {"return": "OK", "message": "coalesced"})
        result = _send_command({"command": "reload-rules"})
        _write_reload_state({"completed_at": _time.time(), "result": result})
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
