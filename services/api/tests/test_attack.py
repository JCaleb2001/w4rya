"""Tests for attack.py — exploit replay and exploit-farm script generation.

Runs a real localhost TCP server per test (no external network, no DB) so the
socket-handling paths (timeout-as-eof, connection refused, deadline budget,
MAX_TARGETS truncation) get exercised the same way they behave in prod,
instead of just the pure build_payload()/_hex_block() helpers test_pure.py
already covers.
"""

from __future__ import annotations

import socket
import threading

import pytest


class _Item:
    def __init__(self, direction, kind, data):
        self.direction = direction
        self.kind = kind
        self.data = data


class _Flow:
    def __init__(self, items, port_dst=1234, flow_id="11111111-1111-1111-1111-111111111111"):
        self.items = items
        self.port_dst = port_dst
        self.id = flow_id


def _echo_server(response: bytes, delay: float = 0.0, clients: int = 1):
    """Bind an ephemeral localhost port, accept `clients` connections
    (each handled on its own thread so concurrent callers don't block each
    other), drain each request, sleep `delay`, send `response`, close.
    Returns (ip, port, thread) — join the thread after the test is done.
    """
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(clients)
    ip, port = srv.getsockname()

    def _handle(conn):
        try:
            conn.settimeout(2.0)
            try:
                conn.recv(65536)
            except OSError:
                pass
            if delay:
                import time
                time.sleep(delay)
            if response:
                try:
                    conn.sendall(response)
                except OSError:
                    pass
        finally:
            conn.close()

    def _accept_loop():
        handlers = []
        for _ in range(clients):
            try:
                conn, _ = srv.accept()
            except OSError:
                break
            h = threading.Thread(target=_handle, args=(conn,), daemon=True)
            h.start()
            handlers.append(h)
        for h in handlers:
            h.join(timeout=2)
        srv.close()

    t = threading.Thread(target=_accept_loop, daemon=True)
    t.start()
    return ip, port, t


@pytest.fixture(autouse=True)
def _flag_regex(monkeypatch):
    import app_config
    monkeypatch.setattr(app_config, "get", lambda key: "FLAG{[A-Za-z0-9]+}" if key == "flag_regex" else None)


# -- generate_script ----------------------------------------------------------

def test_generate_script_is_valid_python():
    import attack
    flow = _Flow([_Item("c", "raw", b"GET / HTTP/1.1\r\n\r\n")], port_dst=8080)
    src = attack.generate_script(flow, [{"name": "alpha", "ip": "10.0.0.1"}])
    compile(src, "<generated>", "exec")  # raises SyntaxError if malformed


def test_generate_script_embeds_teams_and_escapes_quotes():
    import attack
    flow = _Flow([_Item("c", "raw", b"x")])
    src = attack.generate_script(flow, [{"name": 'team"quote', "ip": "10.0.0.2"}])
    assert "10.0.0.2" in src
    # The embedded literal must not close the string early on the raw quote.
    compile(src, "<generated>", "exec")


def test_generate_script_skips_teams_without_ip():
    import attack
    flow = _Flow([_Item("c", "raw", b"x")])
    src = attack.generate_script(flow, [{"name": "no-ip"}, {"name": "ok", "ip": "10.0.0.3"}])
    assert "10.0.0.3" in src
    assert "no-ip" not in src


def test_generate_script_empty_teams_is_still_valid():
    import attack
    flow = _Flow([_Item("c", "raw", b"x")])
    src = attack.generate_script(flow, [])
    compile(src, "<generated>", "exec")


# -- suggest_rule -------------------------------------------------------------

def test_suggest_rule_no_payload():
    import attack
    flow = _Flow([], port_dst=8080)
    out = attack.suggest_rule(flow)
    assert out["raw"] is None


def test_suggest_rule_http_anchors_on_uri_path():
    import attack
    flow = _Flow(
        [_Item("c", "raw", b"GET /api/sheets/58ff1592?token=abc HTTP/1.1\r\nHost: x\r\n\r\n")],
        port_dst=8008,
    )
    out = attack.suggest_rule(flow)
    assert out["basis"] == "http_uri"
    assert out["matched"] == "/api/sheets/58ff1592"  # query string stripped
    assert "8008" in out["raw"]
    assert '"GET"' in out["raw"]


def test_suggest_rule_http_strips_quotes_and_backslashes_from_path():
    """A path containing a raw double-quote or backslash must not be able to
    break out of the generated content string."""
    import attack
    flow = _Flow(
        [_Item("c", "raw", b'GET /x"y\\z HTTP/1.1\r\n\r\n')],
        port_dst=80,
    )
    out = attack.suggest_rule(flow)
    assert '"' not in out["matched"]
    assert "\\" not in out["matched"]


def test_suggest_rule_falls_back_to_raw_bytes_for_non_http():
    import attack
    flow = _Flow([_Item("c", "raw", b"\x01\x02\x03binary-protocol-frame")], port_dst=5151)
    out = attack.suggest_rule(flow)
    assert out["basis"] == "raw_bytes"
    assert "5151" in out["raw"]
    assert "|01 02 03" in out["raw"]


def test_suggest_rule_output_parses_as_a_valid_suricata_rule(tmp_path):
    """Feed the generated rule text through Suricata's own parser (not just
    the app's lightweight validator) so a change here can't reintroduce the
    class of bug where a rule looked fine to `rules.py` but Suricata itself
    rejected it at load time. Skips outside the suricata container — this
    api image doesn't ship the suricata binary, only the sibling container
    running the actual engine does."""
    import shutil
    import subprocess
    import attack

    suricata_bin = shutil.which("suricata")
    if not suricata_bin:
        pytest.skip("suricata binary not available in this environment")

    cases = [
        _Flow([_Item("c", "raw", b'GET /api/sheets/1?x=1 HTTP/1.1\r\n\r\n')], port_dst=8008),
        _Flow([_Item("c", "raw", b"\x01\x02\x03binary")], port_dst=5151),
    ]
    lines = []
    for i, flow in enumerate(cases):
        raw = attack.suggest_rule(flow)["raw"]
        # Every suggested rule ends in ";)" — insert a unique sid before the
        # closing paren so Suricata (which requires one per rule) accepts it.
        assert raw.endswith(";)")
        lines.append(raw[:-1] + f" sid:{9000000 + i};)")

    rules_file = tmp_path / "suggested.rules"
    rules_file.write_text("\n".join(lines))
    proc = subprocess.run(
        [suricata_bin, "-T", "-c", "/etc/suricata/suricata.yaml", "-S", str(rules_file), "-l", "/tmp"],
        capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode == 0, proc.stderr


# -- _replay_one / replay: real localhost sockets -----------------------------

def test_replay_one_matches_flag_in_response():
    import attack
    import re
    ip, port, t = _echo_server(b"here you go: FLAG{abc123}\n")
    try:
        result = attack._replay_one(
            "alpha", ip, port, b"give me the flag",
            timeout=2.0, flag_re=re.compile(rb"FLAG\{[A-Za-z0-9]+\}"),
        )
    finally:
        t.join(timeout=2)
    assert result.ok is True
    assert result.flags == ["FLAG{abc123}"]
    assert result.response_size == len(b"here you go: FLAG{abc123}\n")


def test_replay_one_connection_refused():
    import attack
    import re
    # Bind and immediately close to get a port nothing is listening on.
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    _, dead_port = probe.getsockname()
    probe.close()

    result = attack._replay_one(
        "alpha", "127.0.0.1", dead_port, b"payload",
        timeout=2.0, flag_re=re.compile(rb"never"),
    )
    assert result.ok is False
    assert result.error


def test_replay_one_timeout_is_treated_as_clean_eof():
    """A target that accepts but never answers should end via socket.timeout,
    which attack.py documents as the expected end-of-stream signal, not a
    failure — the call should still report ok=True with an empty body."""
    import attack
    import re
    ip, port, t = _echo_server(response=b"", delay=0)  # never sends anything
    try:
        result = attack._replay_one(
            "alpha", ip, port, b"payload",
            timeout=0.3, flag_re=re.compile(rb"FLAG"),
        )
    finally:
        t.join(timeout=2)
    assert result.ok is True
    assert result.response_size == 0
    assert result.flags == []


def test_replay_multiple_targets_all_complete():
    """Two named targets both pointed at the same test server: verifies
    replay()'s ThreadPoolExecutor path attributes each result back to the
    right team_name rather than mixing them up, and waits for both."""
    import attack
    ip, port, t = _echo_server(b"FLAG{one11111}", clients=2)
    try:
        flow = _Flow([_Item("c", "raw", b"req")], port_dst=port)
        out = attack.replay(flow, [
            {"name": "alpha", "ip": ip},
            {"name": "bravo", "ip": ip},
        ], timeout=2.0)
    finally:
        t.join(timeout=2)
    assert out["payload_size"] == len(b"req")
    assert len(out["results"]) == 2
    names = {r["team_name"] for r in out["results"]}
    assert names == {"alpha", "bravo"}


def test_replay_respects_max_targets():
    import attack
    ip, port, t = _echo_server(b"", clients=attack.MAX_TARGETS)
    try:
        flow = _Flow([_Item("c", "raw", b"req")], port_dst=port)
        many_targets = [{"name": f"t{i}", "ip": ip} for i in range(attack.MAX_TARGETS + 20)]
        out = attack.replay(flow, many_targets, timeout=1.0)
    finally:
        t.join(timeout=2)
    assert len(out["results"]) == attack.MAX_TARGETS


def test_replay_empty_payload_short_circuits_without_connecting():
    import attack
    flow = _Flow([], port_dst=9999)  # no client items -> empty payload
    out = attack.replay(flow, [{"name": "alpha", "ip": "127.0.0.1"}])
    assert out["payload_size"] == 0
    assert out["results"] == []


def test_replay_no_targets_short_circuits():
    import attack
    flow = _Flow([_Item("c", "raw", b"req")], port_dst=9999)
    out = attack.replay(flow, [])
    assert out["results"] == []


def test_replay_echoes_flow_id_in_result():
    import attack
    flow = _Flow([_Item("c", "raw", b"req")], port_dst=9999,
                 flow_id="22222222-2222-2222-2222-222222222222")
    out = attack.replay(flow, [])
    assert out["flow_id"] == "22222222-2222-2222-2222-222222222222"


# -- replay_payload() / generate_script_from_payload() -----------------------
# The saved-exploit-library path: same logic as replay()/generate_script(),
# taking raw bytes + port directly since a saved exploit has no live Flow
# (its payload was snapshotted at save time).

def test_replay_payload_matches_flag_and_echoes_result_id():
    import attack
    ip, port, t = _echo_server(b"FLAG{fromsaved}")
    try:
        out = attack.replay_payload(
            b"req", port, [{"name": "alpha", "ip": ip}],
            timeout=2.0, result_id="saved-exploit-id-123",
        )
    finally:
        t.join(timeout=2)
    assert out["flow_id"] == "saved-exploit-id-123"
    assert out["results"][0]["flags"] == ["FLAG{fromsaved}"]


def test_replay_payload_empty_payload_short_circuits():
    import attack
    out = attack.replay_payload(b"", 9999, [{"name": "a", "ip": "127.0.0.1"}], result_id="x")
    assert out["payload_size"] == 0
    assert out["results"] == []
    assert out["flow_id"] == "x"


def test_generate_script_from_payload_is_valid_python_and_embeds_id():
    import attack
    src = attack.generate_script_from_payload(
        b"GET / HTTP/1.1\r\n\r\n", 8080, "saved-exploit-id-456",
        [{"name": "alpha", "ip": "10.0.0.1"}],
    )
    compile(src, "<generated>", "exec")
    assert "saved-exploit-id-456" in src
    assert "10.0.0.1" in src


def test_replay_one_rewrites_host_header_when_requested():
    """The actual bytes that hit the wire must carry the target's ip:port
    in the Host header, not whatever the payload was captured with —
    otherwise a vhost-routed service silently mis-routes/rejects the
    replay against every team but the one it was captured from."""
    import attack
    import re
    received: list[bytes] = []
    ip, port, t = _echo_server(b"")
    payload = b"GET /x HTTP/1.1\r\nHost: 10.100.2.1:8000\r\n\r\n"

    # Reuse the echo server's accept loop indirectly isn't enough here since
    # it discards what it received — stand up a minimal capturing server.
    import socket as _socket
    import threading as _threading
    srv = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
    srv.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    cap_ip, cap_port = srv.getsockname()

    def _accept():
        conn, _ = srv.accept()
        conn.settimeout(2.0)
        try:
            received.append(conn.recv(65536))
        except OSError:
            received.append(b"")
        conn.close()
        srv.close()

    th = _threading.Thread(target=_accept, daemon=True)
    th.start()
    try:
        attack._replay_one(
            "alpha", cap_ip, cap_port, payload,
            timeout=2.0, flag_re=re.compile(rb"never"), rewrite_host=True,
        )
    finally:
        th.join(timeout=2)
    assert received[0] == f"GET /x HTTP/1.1\r\nHost: {cap_ip}:{cap_port}\r\n\r\n".encode()


def test_replay_one_leaves_host_header_alone_by_default():
    import attack
    import re
    payload = b"GET /x HTTP/1.1\r\nHost: 10.100.2.1:8000\r\n\r\n"
    ip, port, t, received = None, None, None, None

    import socket as _socket
    import threading as _threading
    srv = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
    srv.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    cap_ip, cap_port = srv.getsockname()
    got: list[bytes] = []

    def _accept():
        conn, _ = srv.accept()
        conn.settimeout(2.0)
        try:
            got.append(conn.recv(65536))
        except OSError:
            got.append(b"")
        conn.close()
        srv.close()

    th = _threading.Thread(target=_accept, daemon=True)
    th.start()
    try:
        attack._replay_one(
            "alpha", cap_ip, cap_port, payload,
            timeout=2.0, flag_re=re.compile(rb"never"),
        )  # rewrite_host defaults to False
    finally:
        th.join(timeout=2)
    assert got[0] == payload


def test_replay_payload_threads_rewrite_host_through_to_each_target():
    import attack
    payload = b"GET /x HTTP/1.1\r\nHost: original.example\r\n\r\n"

    import socket as _socket
    import threading as _threading
    srv = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
    srv.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    cap_ip, cap_port = srv.getsockname()
    got: list[bytes] = []

    def _accept():
        conn, _ = srv.accept()
        conn.settimeout(2.0)
        try:
            got.append(conn.recv(65536))
        except OSError:
            got.append(b"")
        conn.close()
        srv.close()

    th = _threading.Thread(target=_accept, daemon=True)
    th.start()
    try:
        attack.replay_payload(
            payload, cap_port, [{"name": "alpha", "ip": cap_ip}],
            timeout=2.0, rewrite_host=True,
        )
    finally:
        th.join(timeout=2)
    assert f"Host: {cap_ip}:{cap_port}".encode() in got[0]
    assert b"original.example" not in got[0]


def test_generate_script_delegates_to_generate_script_from_payload():
    """generate_script(flow, ...) must produce the same output
    generate_script_from_payload(...) would for that flow's own
    payload/port/id — locks in the refactor as a pure delegation."""
    import attack
    flow = _Flow([_Item("c", "raw", b"GET / HTTP/1.1\r\n\r\n")], port_dst=8080,
                 flow_id="33333333-3333-3333-3333-333333333333")
    teams = [{"name": "alpha", "ip": "10.0.0.1"}]
    via_flow = attack.generate_script(flow, teams)
    via_payload = attack.generate_script_from_payload(
        b"GET / HTTP/1.1\r\n\r\n", 8080, "33333333-3333-3333-3333-333333333333", teams,
    )
    assert via_flow == via_payload
