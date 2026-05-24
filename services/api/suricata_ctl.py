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
from typing import Any

SOCKET_PATH = os.environ.get(
    "W4RYA_SURICATA_SOCKET", "/var/run/suricata/suricata-command.socket"
)
DEFAULT_TIMEOUT = 1.5


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


def reload_rules() -> dict:
    """Ask Suricata to re-read the rules file. Returns the raw response dict."""
    return _send_command({"command": "reload-rules"})


def uptime() -> dict:
    """Health check — also confirms the socket protocol is reachable."""
    return _send_command({"command": "uptime"})


def available() -> bool:
    """True iff Suricata is reachable right now (used by the UI to grey out
    the reload button when there's no point)."""
    return os.path.exists(SOCKET_PATH)
