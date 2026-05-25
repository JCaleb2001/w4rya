"""Exploit replay for w4rya.

Given a captured flow, build the client-side payload (all `c` direction items
concatenated) and replay it against a set of enemy team IPs on the original
destination port. Capture responses, regex-match the configured flag pattern,
return a per-target summary.

Also exposes a script generator that emits a standalone Python replayer
(payload embedded as hex) for use in the team's exploit farm.

NO AI: matching is plain `re.findall` against the user-configured flag_regex.
"""

from __future__ import annotations

import re
import socket
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, wait, ALL_COMPLETED
from dataclasses import dataclass
from typing import Optional

import app_config

DEFAULT_TIMEOUT = 3.0
MAX_TIMEOUT = 15.0
MAX_RECV_BYTES = 256 * 1024
EXCERPT_BYTES = 1024
MAX_TARGETS = 64
# Hard ceiling for the whole replay call. Must stay well under gunicorn's -t
# (currently 60s in Dockerfile-api) so worker doesn't get killed mid-replay.
OVERALL_DEADLINE_SEC = 45.0


@dataclass
class ReplayResult:
    team_name: str
    target_ip: str
    ok: bool
    latency_ms: int = 0
    response_size: int = 0
    response_excerpt: str = ""
    flags: Optional[list[str]] = None
    error: Optional[str] = None

    def to_dict(self) -> dict:
        d = {
            "team_name": self.team_name,
            "target_ip": self.target_ip,
            "ok": self.ok,
            "latency_ms": self.latency_ms,
            "response_size": self.response_size,
            "response_excerpt": self.response_excerpt,
        }
        if self.flags is not None:
            d["flags"] = self.flags
            d["flag_count"] = len(self.flags)
        if self.error:
            d["error"] = self.error
        return d


def build_payload(flow) -> bytes:
    """Concatenate every client→server raw item from a flow."""
    if not flow or not flow.items:
        return b""
    return b"".join(
        item.data
        for item in flow.items
        if item.direction == "c" and item.kind == "raw"
    )


def _replay_one(team_name: str, ip: str, port: int, payload: bytes,
                timeout: float, flag_re: re.Pattern[bytes]) -> ReplayResult:
    start = time.monotonic()
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        sock.settimeout(timeout)
        try:
            sock.sendall(payload)
        except OSError as e:
            return ReplayResult(team_name, ip, ok=False, error=f"send: {e!s}")

        chunks: list[bytes] = []
        total = 0
        try:
            while True:
                buf = sock.recv(8192)
                if not buf:
                    break
                chunks.append(buf)
                total += len(buf)
                if total >= MAX_RECV_BYTES:
                    break
        except socket.timeout:
            pass  # timeout is the expected end-of-stream signal for many protocols
        except OSError as e:
            return ReplayResult(team_name, ip, ok=False, error=f"recv: {e!s}")
        finally:
            try:
                sock.close()
            except OSError:
                pass

        body = b"".join(chunks)
        elapsed_ms = int((time.monotonic() - start) * 1000)
        flags = [
            m.decode("latin-1", errors="replace") for m in flag_re.findall(body)
        ]
        excerpt_bytes = body[:EXCERPT_BYTES]
        return ReplayResult(
            team_name=team_name,
            target_ip=ip,
            ok=True,
            latency_ms=elapsed_ms,
            response_size=len(body),
            response_excerpt=excerpt_bytes.decode("latin-1", errors="replace"),
            flags=flags,
        )
    except (socket.gaierror, OSError) as e:
        return ReplayResult(team_name, ip, ok=False, error=f"{type(e).__name__}: {e!s}")


def replay(flow, targets: list[dict], timeout: float = DEFAULT_TIMEOUT) -> dict:
    """Replay `flow`'s client payload against each target.

    `targets`: list of {"name": str, "ip": str}
    """
    targets = targets[:MAX_TARGETS]
    timeout = max(0.5, min(MAX_TIMEOUT, timeout))
    payload = build_payload(flow)
    port = int(flow.port_dst)

    flag_pattern = app_config.get("flag_regex") or ""
    try:
        flag_re = re.compile(flag_pattern.encode())
    except re.error:
        flag_re = re.compile(rb"$.^")  # never matches

    if not payload or not targets:
        return {
            "flow_id": str(flow.id),
            "port": port,
            "payload_size": len(payload),
            "results": [],
        }

    workers = min(16, len(targets))
    # D1: overall deadline so a few slow targets can't pin a gunicorn worker
    # for longer than the worker timeout (-t in Dockerfile-api).
    deadline = min(
        OVERALL_DEADLINE_SEC,
        max(timeout * 3, timeout + 5),
    )
    deadline_at = time.monotonic() + deadline
    with ThreadPoolExecutor(max_workers=workers) as ex:
        fut_map: dict = {}
        for t in targets:
            if not t.get("ip"):
                continue
            name = str(t.get("name") or t["ip"])
            ip = str(t["ip"])
            f = ex.submit(_replay_one, name, ip, port, payload, timeout, flag_re)
            fut_map[f] = (name, ip)

        remaining = max(0.5, deadline_at - time.monotonic())
        done, undone = wait(fut_map.keys(), timeout=remaining, return_when=ALL_COMPLETED)
        results: list[ReplayResult] = [f.result() for f in done]
        for f in undone:
            f.cancel()
            name, ip = fut_map[f]
            results.append(ReplayResult(
                team_name=name,
                target_ip=ip,
                ok=False,
                error="deadline exceeded — overall replay budget hit",
            ))

    return {
        "flow_id": str(flow.id),
        "port": port,
        "payload_size": len(payload),
        "timeout_s": timeout,
        "overall_deadline_s": deadline,
        "results": [r.to_dict() for r in results],
    }


# --- Script generator ------------------------------------------------------

_SCRIPT_TEMPLATE = '''\
#!/usr/bin/env python3
"""Auto-generated by w4rya from flow {flow_id}.

Replays the captured client payload against every TEAM listed below.
Prints any flag matches per team. Drop this into your exploit farm and
adapt main() to whatever submission protocol you use.

NO external dependencies — stdlib only.
"""
import re
import socket
import sys

# (name, ip) — edit / extend as needed.
TEAMS = {teams_repr}

PORT = {port}
TIMEOUT = {timeout}
MAX_RECV_BYTES = {max_recv}
FLAG_RE = re.compile(rb"{flag_regex}")

# Captured request payload (client -> server bytes).
PAYLOAD = bytes.fromhex(
{payload_hex}
)


def replay(name: str, ip: str):
    try:
        sock = socket.create_connection((ip, PORT), timeout=TIMEOUT)
        sock.settimeout(TIMEOUT)
        sock.sendall(PAYLOAD)
        chunks = []
        total = 0
        try:
            while True:
                buf = sock.recv(8192)
                if not buf:
                    break
                chunks.append(buf)
                total += len(buf)
                if total >= MAX_RECV_BYTES:
                    break
        except socket.timeout:
            pass
        sock.close()
        body = b"".join(chunks)
    except OSError as e:
        print(f"[!] {{name:20s}} {{ip:15s}}  err: {{e}}", file=sys.stderr)
        return []
    flags = [m.decode("latin-1", errors="replace") for m in FLAG_RE.findall(body)]
    if flags:
        print(f"[+] {{name:20s}} {{ip:15s}}  FLAGS={{flags!r}}")
    else:
        print(f"[ ] {{name:20s}} {{ip:15s}}  no flag in {{len(body)}}B response")
    return flags


def main():
    captured = []
    for name, ip in TEAMS:
        for f in replay(name, ip):
            captured.append((name, ip, f))
    # TODO: pipe `captured` into your farm/submitter here.
    print(f"\\n[w4rya] captured {{len(captured)}} flag(s) total", file=sys.stderr)


if __name__ == "__main__":
    main()
'''


def _hex_block(data: bytes, width: int = 32) -> str:
    """Wrap hex into nicely-indented lines for the generated script."""
    h = data.hex()
    lines: list[str] = []
    chars_per_line = width * 2
    for i in range(0, len(h), chars_per_line):
        chunk = h[i : i + chars_per_line]
        lines.append(f'    "{chunk}"')
    if not lines:
        lines.append('    ""')
    return "\n".join(lines)


def generate_script(flow, teams: list[dict], timeout: float = DEFAULT_TIMEOUT) -> str:
    payload = build_payload(flow)
    port = int(flow.port_dst)
    flag_pattern = app_config.get("flag_regex") or ""

    team_tuples = []
    for t in teams:
        name = str(t.get("name") or "team").replace('"', "'")
        ip = str(t.get("ip") or "")
        if not ip:
            continue
        team_tuples.append((name, ip))
    teams_repr = "[\n" + "\n".join(
        f'    ("{n}", "{ip}"),' for n, ip in team_tuples
    ) + "\n]" if team_tuples else "[]"

    flag_for_re = flag_pattern.replace('\\', '\\\\').replace('"', '\\"')

    return _SCRIPT_TEMPLATE.format(
        flow_id=str(flow.id),
        teams_repr=teams_repr,
        port=port,
        timeout=timeout,
        max_recv=MAX_RECV_BYTES,
        flag_regex=flag_for_re,
        payload_hex=_hex_block(payload),
    )
