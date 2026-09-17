"""Smoke tests for the pure-function paths in the w4rya api.

Runs inside the api container with `docker compose exec api pytest /app/tests/`.
These tests deliberately avoid DB/Flask startup — they just exercise the
isolated modules (rate_limit, app_config.coerce_scalar, rules parser, attack
script generator). The DB-backed paths get exercised by the curl smoke tests
the team runs after a deploy.
"""

from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass

import pytest


# -- rate_limit -------------------------------------------------------------

def test_rate_limit_below_threshold():
    import rate_limit
    rate_limit.clear("k1")
    for _ in range(rate_limit.LOGIN_MAX_FAILS - 1):
        rate_limit.record_failure("k1")
    assert not rate_limit.is_blocked("k1")


def test_rate_limit_at_threshold():
    import rate_limit
    rate_limit.clear("k2")
    for _ in range(rate_limit.LOGIN_MAX_FAILS):
        rate_limit.record_failure("k2")
    assert rate_limit.is_blocked("k2")


def test_rate_limit_clear_resets():
    import rate_limit
    rate_limit.clear("k3")
    for _ in range(rate_limit.LOGIN_MAX_FAILS):
        rate_limit.record_failure("k3")
    assert rate_limit.is_blocked("k3")
    rate_limit.clear("k3")
    assert not rate_limit.is_blocked("k3")


def test_rate_limit_window_expiry():
    import rate_limit
    key = "k4"
    rate_limit.clear(key)
    # 5 failures with a tiny window — block, then verify they expire.
    for _ in range(5):
        rate_limit.record_failure(key, window=0.05)
    assert rate_limit.is_blocked(key, window=0.05, max_fails=5)
    time.sleep(0.1)
    assert not rate_limit.is_blocked(key, window=0.05, max_fails=5)


def test_rate_limit_seconds_until_unblock_zero_when_open():
    import rate_limit
    rate_limit.clear("k5")
    assert rate_limit.seconds_until_unblock("k5") == 0


# -- app_config.coerce_scalar ----------------------------------------------

def test_coerce_int_keys():
    import app_config
    assert app_config.coerce_scalar("tick_length", "180000") == 180000
    assert app_config.coerce_scalar("flag_lifetime", 5) == 5


def test_coerce_bool_variants():
    import app_config
    for truthy in (True, 1, "true", "1", "Yes", " on ", "ON"):
        assert app_config.coerce_scalar("rules_autoreload", truthy) is True, truthy
    for falsy in (False, 0, "false", "no", "", "garbage"):
        assert app_config.coerce_scalar("rules_autoreload", falsy) is False, falsy


def test_coerce_flag_regex_valid():
    import app_config
    s = app_config.coerce_scalar("flag_regex", "[A-Z0-9]{31}=")
    assert s == "[A-Z0-9]{31}="


def test_coerce_flag_regex_invalid_syntax_raises():
    import app_config
    with pytest.raises(ValueError, match="invalid regex"):
        app_config.coerce_scalar("flag_regex", "(unclosed")


def test_coerce_flag_regex_redos_raises():
    import app_config
    with pytest.raises(ValueError, match="ReDoS|nested"):
        app_config.coerce_scalar("flag_regex", "(.+)+x")


def test_coerce_string_passthrough():
    import app_config
    assert app_config.coerce_scalar("vm_ip", "10.10.3.1") == "10.10.3.1"
    assert app_config.coerce_scalar("visualizer_url", "") == ""


# -- rules.parse_one --------------------------------------------------------

def test_parse_valid_alert():
    import rules
    r = rules.parse_one(
        'alert http any any -> any any (msg:"first"; content:"foo"; sid:1; rev:1;)\n'
    )
    assert r is not None
    assert r.enabled
    assert r.parsed
    assert r.sid == 1
    assert r.action == "alert"
    assert r.msg == "first"


def test_parse_disabled_with_hash():
    import rules
    r = rules.parse_one(
        '# alert http any any -> any any (msg:"x"; sid:42; rev:1;)\n'
    )
    assert r is not None
    assert not r.enabled
    assert r.sid == 42


def test_parse_blank_returns_none():
    import rules
    assert rules.parse_one("") is None
    assert rules.parse_one("   \n") is None


def test_parse_pure_comment_returns_none():
    import rules
    assert rules.parse_one("# this is a comment, not a rule\n") is None


def test_parse_garbage_keeps_raw():
    import rules
    r = rules.parse_one(
        "alert http any any -> any any (this isn't really a valid body; sid:99;)\n"
    )
    assert r is not None
    # the body parses but content fields aren't recognized; raw is preserved
    assert r.sid == 99


# -- rules._inject_sid -----------------------------------------------------

def test_inject_sid_adds_when_missing():
    import rules
    out = rules._inject_sid('alert tcp any any -> any 22 (msg:"x";)', 1000000)
    assert "sid:1000000;" in out
    assert "rev:1;" in out


def test_inject_sid_no_op_when_present():
    import rules
    raw = 'alert tcp any any -> any 22 (msg:"x"; sid:123; rev:7;)'
    assert rules._inject_sid(raw, 999) == raw  # unchanged


def test_inject_sid_no_duplicate_rev_when_present():
    import rules
    out = rules._inject_sid(
        'alert tcp any any -> any 22 (msg:"x"; rev:5;)', 1000000
    )
    # rev:5 was already there; we should NOT add another rev:1
    assert out.count("rev:") == 1


def test_inject_sid_refuses_unbalanced_parens():
    import rules
    with pytest.raises(ValueError, match="unbalanced parens"):
        rules._inject_sid('alert tcp any any -> any 22 (msg:"x"', 1)


def test_inject_sid_appends_body_when_no_parens():
    import rules
    out = rules._inject_sid("alert tcp any any -> any 22", 7)
    assert "(sid:7" in out
    assert out.endswith(")")


# -- rules add/save round-trip with tempdir ---------------------------------

def test_rules_round_trip_with_tempfile(tmp_path, monkeypatch):
    """Add + list + toggle enabled + delete, against a real on-disk file."""
    import rules

    rules_file = tmp_path / "suricata.rules"
    monkeypatch.setattr(rules, "RULES_FILE", str(rules_file))

    # start empty
    assert rules.load() == []

    # add 2 rules
    r1 = rules.add('alert tcp any any -> any 22 (msg:"ssh";)')
    r2 = rules.add('drop tcp any any -> any 23 (msg:"telnet";)')
    assert r1.sid >= rules.AUTO_SID_START
    assert r2.sid == r1.sid + 1

    listing = rules.load()
    assert len(listing) == 2
    sids = {r.sid for r in listing}
    assert sids == {r1.sid, r2.sid}

    # disable r2 and re-load
    updated = rules.update_one(r2.sid, enabled=False)
    assert updated is not None
    assert not updated.enabled
    after = {r.sid: r for r in rules.load()}
    assert not after[r2.sid].enabled
    # the on-disk line should be prefixed with '# '
    raw_text = rules_file.read_text()
    assert any(line.lstrip().startswith("# drop") for line in raw_text.splitlines())

    # re-enable, then verify
    updated = rules.update_one(r2.sid, enabled=True)
    assert updated is not None
    assert updated.enabled
    raw_text = rules_file.read_text()
    assert any(line.startswith("drop ") for line in raw_text.splitlines())

    # delete r1
    assert rules.delete(r1.sid) is True
    assert rules.delete(r1.sid) is False  # already gone
    assert {r.sid for r in rules.load()} == {r2.sid}


def test_rules_block_ip_writes_drop_rule(tmp_path, monkeypatch):
    import rules
    rules_file = tmp_path / "suricata.rules"
    monkeypatch.setattr(rules, "RULES_FILE", str(rules_file))

    r = rules.block_ip("1.2.3.4")
    assert r.action == "drop"
    assert "1.2.3.4" in r.raw
    assert r.sid >= rules.AUTO_SID_START


def test_rules_block_ip_refuses_quote_injection():
    import rules
    with pytest.raises(ValueError):
        rules.block_ip('"; injected')


# -- attack script generation ----------------------------------------------

def test_hex_block_format():
    import attack
    out = attack._hex_block(b"abc")
    # 3 bytes -> 6 hex chars; should be a single indented quoted line
    assert '"616263"' in out


def test_hex_block_wraps_long():
    import attack
    out = attack._hex_block(b"x" * 100)
    # 100 bytes -> 200 hex chars, wrapped at 64 chars per line (width 32)
    lines = [l for l in out.split("\n") if l.strip()]
    assert len(lines) >= 2


def test_hex_block_empty():
    import attack
    out = attack._hex_block(b"")
    assert '""' in out


def test_build_payload_with_no_items():
    """build_payload should return empty bytes for a flow with no client items."""
    import attack
    class F:
        items = []
    assert attack.build_payload(F()) == b""


def test_build_payload_concatenates_client_items_only():
    import attack
    class Item:
        def __init__(self, direction, kind, data):
            self.direction = direction
            self.kind = kind
            self.data = data
    class F:
        items = [
            Item("c", "raw", b"AAA"),
            Item("s", "raw", b"SERVER_RESPONSE"),
            Item("c", "raw", b"BBB"),
            Item("c", "decoded", b"NOT_RAW"),
        ]
    assert attack.build_payload(F()) == b"AAABBB"


# -- webservice.py's replay-override parsing (shared by /attack/replay and
# /exploits/<id>/replay: ad-hoc target IP/port + editable payload text) -----

def test_parse_targets_accepts_bare_strings_and_dicts():
    import webservice
    out = webservice._parse_targets(["1.2.3.4", {"name": "bravo", "ip": "5.6.7.8"}])
    assert out == [
        {"name": "1.2.3.4", "ip": "1.2.3.4"},
        {"name": "bravo", "ip": "5.6.7.8"},
    ]


def test_parse_targets_dict_without_ip_is_dropped():
    import webservice
    out = webservice._parse_targets([{"name": "no-ip"}, {"name": "ok", "ip": "1.1.1.1"}])
    assert out == [{"name": "ok", "ip": "1.1.1.1"}]


def test_parse_targets_dict_defaults_name_to_ip():
    import webservice
    out = webservice._parse_targets([{"ip": "9.9.9.9"}])
    assert out == [{"name": "9.9.9.9", "ip": "9.9.9.9"}]


def test_parse_targets_empty_or_missing_is_none():
    import webservice
    assert webservice._parse_targets([]) is None
    assert webservice._parse_targets(None) is None
    assert webservice._parse_targets("not-a-list") is None


def test_parse_timeout_defaults_and_rejects_garbage():
    import attack
    import webservice
    assert webservice._parse_timeout({}) == attack.DEFAULT_TIMEOUT
    assert webservice._parse_timeout({"timeout": "nope"}) == attack.DEFAULT_TIMEOUT
    assert webservice._parse_timeout({"timeout": 5.5}) == 5.5


def test_parse_port_override_none_when_absent():
    import webservice
    assert webservice._parse_port_override({}) is None
    assert webservice._parse_port_override({"port": ""}) is None


def test_parse_port_override_valid():
    import webservice
    assert webservice._parse_port_override({"port": 8080}) == 8080
    assert webservice._parse_port_override({"port": "8080"}) == 8080


def test_parse_port_override_out_of_range_raises():
    import webservice
    with pytest.raises(ValueError):
        webservice._parse_port_override({"port": 70000})
    with pytest.raises(ValueError):
        webservice._parse_port_override({"port": 0})


def test_parse_payload_override_none_when_absent():
    import webservice
    assert webservice._parse_payload_override({}) is None


def test_parse_payload_override_round_trips_every_byte_value():
    """latin-1 must losslessly round-trip all 256 byte values — the whole
    point of using it as the payload editor's text encoding instead of utf-8
    (which would reject or mangle arbitrary binary payloads)."""
    import webservice
    raw = bytes(range(256))
    text = raw.decode("latin-1")
    out = webservice._parse_payload_override({"payload_text": text})
    assert out == raw


def test_parse_payload_override_rejects_non_string():
    import webservice
    with pytest.raises(ValueError):
        webservice._parse_payload_override({"payload_text": 12345})


# -- attack.rewrite_host_header() --------------------------------------------

def test_rewrite_host_header_replaces_existing_header():
    import attack
    payload = b"GET /x HTTP/1.1\r\nHost: 10.100.2.1:8000\r\nUser-Agent: x\r\n\r\n"
    out = attack.rewrite_host_header(payload, "10.50.0.7", 9999)
    assert b"Host: 10.50.0.7:9999\r\n" in out
    assert b"10.100.2.1" not in out
    # Everything else in the request is untouched.
    assert b"GET /x HTTP/1.1\r\n" in out
    assert b"User-Agent: x\r\n" in out


def test_rewrite_host_header_omits_port_for_80_and_443():
    import attack
    payload = b"GET / HTTP/1.1\r\nHost: old.example\r\n\r\n"
    assert b"Host: 1.2.3.4\r\n" in attack.rewrite_host_header(payload, "1.2.3.4", 80)
    assert b"Host: 1.2.3.4\r\n" in attack.rewrite_host_header(payload, "1.2.3.4", 443)
    assert b"Host: 1.2.3.4:8080\r\n" in attack.rewrite_host_header(payload, "1.2.3.4", 8080)


def test_rewrite_host_header_is_case_insensitive_and_only_replaces_first_match():
    import attack
    payload = b"GET / HTTP/1.1\r\nhost: a.example\r\nX-Forwarded-Host: b.example\r\n\r\n"
    out = attack.rewrite_host_header(payload, "9.9.9.9", 80)
    assert out.count(b"Host: 9.9.9.9") == 1
    # A different header that merely contains "Host" in its name is untouched.
    assert b"X-Forwarded-Host: b.example" in out


def test_rewrite_host_header_noop_for_non_http_payload():
    import attack
    payload = b"\x01\x02\x03binary-protocol-frame-no-host-header"
    assert attack.rewrite_host_header(payload, "1.2.3.4", 1234) == payload


def test_rewrite_host_header_noop_for_empty_payload():
    import attack
    assert attack.rewrite_host_header(b"", "1.2.3.4", 80) == b""


# -- attack.is_http_request() / raw_socket_snippet() -------------------------
# The other half of the "📋 Copy Exploit" crash fix: data2req.py's HTTP
# converters assume every item is an HTTP request and raise (not degrade)
# when fed a bare-TCP payload — is_http_request gates that path so
# non-HTTP services fall back to raw_socket_snippet instead of a 500.

def test_is_http_request_true_for_a_real_request_line():
    import attack
    assert attack.is_http_request(b"GET /x HTTP/1.1\r\nHost: y\r\n\r\n") is True
    assert attack.is_http_request(b"POST /x HTTP/1.0\r\n\r\n") is True


def test_is_http_request_false_for_raw_tcp_payload():
    import attack
    assert attack.is_http_request(b"Enter authorization code: ") is False
    assert attack.is_http_request(b"\x01\x02\x03binary-protocol-frame") is False


def test_is_http_request_false_for_empty_payload():
    import attack
    assert attack.is_http_request(b"") is False


def test_raw_socket_snippet_is_valid_python_and_embeds_payload_and_port():
    import attack
    src = attack.raw_socket_snippet(b"Enter authorization code: ", 5151)
    compile(src, "<generated>", "exec")
    assert "5151" in src
    assert repr(b"Enter authorization code: ") in src


def test_raw_socket_snippet_handles_binary_payload_safely():
    """Payload bytes containing quotes/backslashes/non-printables must not
    break the generated source — repr() handles all of that; this locks in
    that raw_socket_snippet doesn't try to format bytes manually."""
    import attack
    payload = b'weird"bytes\\here\x00\x01\xff'
    src = attack.raw_socket_snippet(payload, 1234)
    compile(src, "<generated>", "exec")


# -- attack.rule_content_clauses() / find_exploit_item() ---------------------
# The "📋 Copy Exploit" button's core: isolate which client item in a
# multi-request flow the firing rule actually matched, so the operator gets
# just the one malicious request instead of the whole captured session.

class _Item:
    def __init__(self, direction, kind, data):
        self.direction = direction
        self.kind = kind
        self.data = data


@dataclass
class _Flow:
    items: list

    # narrow_flow_to_items uses dataclasses.replace(), which requires the
    # instance's own type to be a dataclass too.


@pytest.fixture
def rules_files(tmp_path, monkeypatch):
    """Point attack.py's sid lookup at throwaway rule files instead of the
    real ones, so these tests don't depend on suricata-rules/ contents."""
    import attack
    import rules
    custom = tmp_path / "custom.rules"
    et_open = tmp_path / "et-open.rules"
    et_open.parent.mkdir(exist_ok=True)
    custom.write_text("")
    et_open.write_text("")
    monkeypatch.setattr(rules, "RULES_FILE", str(custom))
    monkeypatch.setattr(attack, "_ET_OPEN_RULES_FILE", str(et_open))
    return custom, et_open


def test_rule_content_clauses_plain_content_defaults_to_pkt_buffer(rules_files):
    """No sticky buffer active -> Suricata matches the raw packet payload,
    which is what buffer "pkt" means here."""
    import attack
    custom, _ = rules_files
    custom.write_text(
        'alert http any any -> any any (msg:"x"; content:"jndi:"; nocase; sid:1000009;)\n'
    )
    clauses = attack.rule_content_clauses(1000009)
    assert clauses == [(b"jndi:", "contains", "pkt")]


def test_rule_content_clauses_endswith_modifier_and_buffer_detected(rules_files):
    import attack
    custom, _ = rules_files
    custom.write_text(
        'alert http any any -> any 8000 (msg:"x"; http.method; content:"GET"; '
        'http.uri; content:"/api/route"; endswith; sid:1000007;)\n'
    )
    clauses = attack.rule_content_clauses(1000007)
    assert clauses == [(b"get", "contains", "method"), (b"/api/route", "endswith", "uri")]


def test_rule_content_clauses_old_style_postfix_buffer_modifier(rules_files):
    """Old-style `http_uri;` applies BACKWARD to the content immediately
    preceding it — the exact syntax rule 1000008 (IDOR sheets token) uses,
    and the case that motivated buffer-scoped matching in the first place."""
    import attack
    custom, _ = rules_files
    custom.write_text(
        'alert http any any -> any 8008 (msg:"x"; content:"/api/sheets/"; '
        'http_uri; content:"token="; http_uri; sid:1000008;)\n'
    )
    clauses = attack.rule_content_clauses(1000008)
    assert clauses == [(b"/api/sheets/", "contains", "uri"), (b"token=", "contains", "uri")]


def test_rule_content_clauses_postfix_buffer_after_safe_bare_modifier(rules_files):
    """Common real ET-style ordering: a bare modifier like `nocase;` sits
    between the content and its postfix buffer keyword
    (`content:"..."; nocase; http_uri;`). The lookahead must keep scanning
    past `nocase` instead of stopping there and leaving the clause scoped
    to the default "pkt" buffer — which would silently reintroduce
    whole-packet substring matching for this clause."""
    import attack
    custom, _ = rules_files
    custom.write_text(
        'alert http any any -> any 8008 (msg:"x"; content:"token="; nocase; '
        'http_uri; sid:1000410;)\n'
    )
    clauses = attack.rule_content_clauses(1000410)
    assert clauses == [(b"token=", "contains", "uri")]


def test_rule_content_clauses_malformed_hex_run_bails_instead_of_crashing(rules_files):
    """An odd number of `|` in a content clause (malformed hex run) must
    degrade to "can't isolate" (None), not raise ValueError up through
    find_exploit_item to the API layer."""
    import attack
    custom, _ = rules_files
    custom.write_text(
        'alert tcp any any -> any 1433 (msg:"x"; content:"x|00p"; sid:1000411;)\n'
    )
    assert attack.rule_content_clauses(1000411) is None


def test_rule_content_clauses_decodes_hex_bytes(rules_files):
    import attack
    custom, _ = rules_files
    custom.write_text(
        'alert tcp any any -> any 1433 (msg:"x"; '
        'content:"x|00|p|00|_|00|"; nocase; sid:1000018;)\n'
    )
    clauses = attack.rule_content_clauses(1000018)
    assert clauses == [(b"x\x00p\x00_\x00", "contains", "pkt")]


def test_rule_content_clauses_negated_content_returns_none(rules_files):
    """A rule whose only content is a negated (must-NOT-contain) clause has
    nothing we can positively match on."""
    import attack
    custom, _ = rules_files
    custom.write_text(
        'alert http any any -> any any (msg:"x"; content:!"safe"; sid:1000099;)\n'
    )
    assert attack.rule_content_clauses(1000099) is None


def test_rule_content_clauses_pcre_only_rule_returns_none(rules_files):
    import attack
    custom, _ = rules_files
    custom.write_text(
        'alert http any any -> any any (msg:"x"; pcre:"/foo/i"; sid:1000100;)\n'
    )
    assert attack.rule_content_clauses(1000100) is None


def test_rule_content_clauses_sid_not_found_returns_none(rules_files):
    import attack
    assert attack.rule_content_clauses(9999999) is None


def test_rule_content_clauses_falls_back_to_et_open_file(rules_files):
    import attack
    _, et_open = rules_files
    et_open.write_text(
        'alert http any any -> any any (msg:"ET MALWARE x"; content:"beacon"; sid:2030001;)\n'
    )
    assert attack.rule_content_clauses(2030001) == [(b"beacon", "contains", "pkt")]


def test_rule_content_clauses_bails_on_unsupported_buffer_keyword(rules_files):
    """A buffer we don't know how to re-derive from a raw item (http.header
    is far too broad/ambiguous to safely substring-match against) must bail
    the WHOLE rule, not silently treat it as "pkt" or ignore the keyword —
    either of those could pick the wrong item with high confidence."""
    import attack
    custom, _ = rules_files
    custom.write_text(
        'alert http any any -> any any (msg:"x"; http.header; content:"X-Foo"; sid:1000400;)\n'
    )
    assert attack.rule_content_clauses(1000400) is None


def test_rule_content_clauses_bails_on_unsupported_postfix_keyword(rules_files):
    import attack
    custom, _ = rules_files
    custom.write_text(
        'alert dns any any -> any any (msg:"x"; content:"evil.com"; dns_query; sid:1000401;)\n'
    )
    assert attack.rule_content_clauses(1000401) is None


def test_find_exploit_item_single_client_item_is_trivially_isolated(rules_files):
    import attack
    flow = _Flow([_Item("c", "raw", b"GET / HTTP/1.1\r\n\r\n")])
    assert attack.find_exploit_item(flow, None) == (0, "single_item")


def test_find_exploit_item_no_client_items_is_full_flow(rules_files):
    import attack
    flow = _Flow([_Item("s", "raw", b"HTTP/1.1 200 OK\r\n\r\n")])
    assert attack.find_exploit_item(flow, None) == (None, "full_flow")


def test_find_exploit_item_no_sid_with_multiple_items_is_full_flow(rules_files):
    import attack
    flow = _Flow([
        _Item("c", "raw", b"GET /a HTTP/1.1\r\n\r\n"),
        _Item("c", "raw", b"GET /b HTTP/1.1\r\n\r\n"),
    ])
    assert attack.find_exploit_item(flow, None) == (None, "full_flow")


def test_find_exploit_item_isolates_the_matching_endswith_uri(rules_files):
    """The real-world case that motivated endswith-awareness: two items
    share the "/api/route" substring, but only one item's URI actually
    *ends with* it — the other has a trailing /<id>."""
    import attack
    custom, _ = rules_files
    custom.write_text(
        'alert http any any -> any 8000 (msg:"x"; http.method; content:"GET"; '
        'http.uri; content:"/api/route"; endswith; sid:1000007;)\n'
    )
    flow = _Flow([
        _Item("c", "raw", b"POST /api/signup HTTP/1.1\r\nHost: x\r\n\r\n"),
        _Item("s", "raw", b"HTTP/1.1 200 OK\r\n\r\n"),
        _Item("c", "raw", b"GET /api/route HTTP/1.1\r\nHost: x\r\n\r\n"),
        _Item("s", "raw", b"HTTP/1.1 200 OK\r\n\r\n"),
        _Item("c", "raw", b"GET /api/route/abc123 HTTP/1.1\r\nHost: x\r\n\r\n"),
    ])
    assert attack.find_exploit_item(flow, 1000007) == (2, "single_item")


def test_find_exploit_item_multiple_distinct_matches_returns_matched_items(rules_files):
    """Two DIFFERENT requests both satisfy the rule (not a replay of the
    same one) — isolate to just those two instead of giving up entirely."""
    import attack
    custom, _ = rules_files
    custom.write_text(
        'alert http any any -> any any (msg:"x"; content:"/api/"; sid:1000200;)\n'
    )
    flow = _Flow([
        _Item("c", "raw", b"GET /api/a HTTP/1.1\r\n\r\n"),
        _Item("c", "raw", b"GET /api/b HTTP/1.1\r\n\r\n"),
    ])
    assert attack.find_exploit_item(flow, 1000200) == ([0, 1], "matched_items")


def test_find_exploit_item_identical_repeated_matches_collapse_to_single_item(rules_files):
    """A brute-forced/replayed request fires the rule N times with byte-
    identical payloads — there is no meaningful difference between "request
    3 of 40" and "request 37 of 40", so this should NOT dump all 40 into
    the generated script; the first occurrence stands in for all of them."""
    import attack
    custom, _ = rules_files
    custom.write_text(
        'alert http any any -> any any (msg:"x"; http.method; content:"POST"; '
        'http.uri; content:"/nacos/v1/cs/ops/data/removal"; sid:1000201;)\n'
    )
    same_request = b"POST /nacos/v1/cs/ops/data/removal HTTP/1.1\r\nHost: x\r\n\r\n"
    flow = _Flow([_Item("c", "raw", same_request) for _ in range(5)])
    assert attack.find_exploit_item(flow, 1000201) == (0, "single_item")


def test_find_exploit_item_no_content_clauses_falls_back_to_full_flow(rules_files):
    import attack
    custom, _ = rules_files
    custom.write_text('alert http any any -> any any (msg:"x"; pcre:"/foo/"; sid:1000300;)\n')
    flow = _Flow([
        _Item("c", "raw", b"GET /a HTTP/1.1\r\n\r\n"),
        _Item("c", "raw", b"GET /b HTTP/1.1\r\n\r\n"),
    ])
    assert attack.find_exploit_item(flow, 1000300) == (None, "full_flow")


def test_find_exploit_item_does_not_false_match_on_a_cookie_shared_by_every_request(rules_files):
    """The exact bug found by inspecting a real captured session: rule
    1000008 requires "/api/sheets/" AND "token=" both inside the URI
    (http_uri on both clauses). Every authenticated request in this session
    carries `Cookie: auth-token=...`, whose value contains the substring
    "token=" too — if clause matching isn't scoped to the URI buffer, the
    upload request (URI also contains "/api/sheets/") wrongly satisfies
    both clauses via its Cookie header, the match becomes ambiguous (2 items
    instead of 1), and isolation silently falls back to dumping the entire
    5-request session instead of just the one real exploit request."""
    import attack
    custom, _ = rules_files
    custom.write_text(
        'alert http any any -> any 8008 (msg:"x"; content:"/api/sheets/"; '
        'http_uri; content:"token="; http_uri; sid:1000008;)\n'
    )
    auth_cookie = b"Cookie: auth-token=deadbeefdeadbeefdeadbeefdeadbeef\r\n"
    flow = _Flow([
        _Item("c", "raw", b"POST /api/signup HTTP/1.1\r\nHost: x\r\n\r\n{}"),
        _Item("s", "raw", b"HTTP/1.1 200 OK\r\n\r\n"),
        _Item("c", "raw", b"POST /api/signin HTTP/1.1\r\nHost: x\r\n\r\n{}"),
        _Item("s", "raw", b"HTTP/1.1 200 OK\r\n\r\n"),
        _Item("c", "raw", b"POST /api/sheets/upload HTTP/1.1\r\nHost: x\r\n" + auth_cookie + b"\r\n{}"),
        _Item("s", "raw", b"HTTP/1.1 200 OK\r\n\r\n"),
        _Item("c", "raw", b"GET /api/sheets/b06818e2?token=7da31352 HTTP/1.1\r\nHost: x\r\n" + auth_cookie + b"\r\n"),
        _Item("s", "raw", b"HTTP/1.1 200 OK\r\n\r\n"),
        _Item("c", "raw", b"GET /api/sheets HTTP/1.1\r\nHost: x\r\n" + auth_cookie + b"\r\n"),
    ])
    item_index, basis = attack.find_exploit_item(flow, 1000008)
    assert basis == "single_item"
    assert item_index == 6  # only the token-bearing GET, not the upload


def test_find_exploit_item_isolates_via_request_body_buffer(rules_files):
    import attack
    custom, _ = rules_files
    custom.write_text(
        'alert http any any -> any any (msg:"x"; http.request_body; '
        'content:"JdbcRowSetImpl"; sid:1000012;)\n'
    )
    flow = _Flow([
        _Item("c", "raw", b'POST /a HTTP/1.1\r\nHost: x\r\n\r\n{"note":"JdbcRowSetImpl mentioned in URL only? no."}'),
        _Item("c", "raw", b'POST /b HTTP/1.1\r\nHost: x\r\n\r\n{"@type":"com.sun.rowset.JdbcRowSetImpl"}'),
    ])
    # Both bodies happen to mention the string, and they're NOT identical,
    # so both are isolated as distinct matches — the point is that it's
    # evaluated against the BODY (after the blank-line separator), not
    # headers, for both items equally.
    item_index, basis = attack.find_exploit_item(flow, 1000012)
    assert (item_index, basis) == ([0, 1], "matched_items")

    # Now make it unambiguous: only item 1's body actually contains it.
    flow2 = _Flow([
        _Item("c", "raw", b'POST /a HTTP/1.1\r\nHost: x\r\n\r\n{"nothing":"here"}'),
        _Item("c", "raw", b'POST /b HTTP/1.1\r\nHost: x\r\n\r\n{"@type":"com.sun.rowset.JdbcRowSetImpl"}'),
    ])
    item_index, basis = attack.find_exploit_item(flow2, 1000012)
    assert (item_index, basis) == (1, "single_item")


def test_find_exploit_item_many_distinct_matches_are_never_silently_dropped(rules_files):
    """The real Nacos case: a scanner retries the same exploit template 100
    times with a fresh random identifier each attempt, so all 100 requests
    are distinct (not a byte-identical replay) yet all legitimately match
    the rule. Past _MAX_MATCHED_ITEMS these used to collapse to a single
    representative — but that same code path also silently ate a genuine
    multi-stage attack chain longer than the cap, which is worse than a
    long list. Distinct matches are now always returned in full, however
    many there are; only byte-identical duplicates collapse."""
    import attack
    custom, _ = rules_files
    custom.write_text(
        'alert http any any -> any any (msg:"x"; http.uri; content:"/nacos/v1/cs/ops/data/removal"; sid:1000202;)\n'
    )
    n = attack._MAX_MATCHED_ITEMS + 1
    flow = _Flow([
        _Item("c", "raw", f"POST /nacos/v1/cs/ops/data/removal?id={i} HTTP/1.1\r\n\r\n".encode())
        for i in range(n)
    ])
    item_index, basis = attack.find_exploit_item(flow, 1000202)
    assert (item_index, basis) == (list(range(n)), "matched_items")


def test_narrow_flow_to_items_keeps_only_the_given_items_in_order(rules_files):
    import attack
    flow = _Flow([
        _Item("c", "raw", b"first"),
        _Item("s", "raw", b"resp"),
        _Item("c", "raw", b"second"),
        _Item("c", "raw", b"third"),
    ])
    narrowed = attack.narrow_flow_to_items(flow, [2, 0])
    assert [i.data for i in narrowed.items] == [b"second", b"first"]
    # the original is untouched
    assert len(flow.items) == 4


def test_find_exploit_item_unsupported_buffer_keyword_falls_back_to_full_flow(rules_files):
    import attack
    custom, _ = rules_files
    custom.write_text(
        'alert http any any -> any any (msg:"x"; http.header; content:"X-Foo"; sid:1000410;)\n'
    )
    flow = _Flow([
        _Item("c", "raw", b"GET /a HTTP/1.1\r\n\r\n"),
        _Item("c", "raw", b"GET /b HTTP/1.1\r\n\r\n"),
    ])
    assert attack.find_exploit_item(flow, 1000410) == (None, "full_flow")


# -- attack.describe_endpoint() / locate_vulnerable_input() ------------------
# What turns an alert into something the patching team can act on without
# reading a payload dump: which exact endpoint, and which exact input
# (query param / body field / header) the exploit rides in.

def test_describe_endpoint_strips_query_string():
    import attack
    assert attack.describe_endpoint(
        b"GET /api/sheets/abc?token=xyz HTTP/1.1\r\nHost: x\r\n\r\n"
    ) == "GET /api/sheets/abc"


def test_describe_endpoint_none_for_non_http():
    import attack
    assert attack.describe_endpoint(b"Enter authorization code: ") is None


def test_locate_vulnerable_input_pinpoints_query_parameter():
    """The real case that motivated this: rule 1000008 requires
    "/api/sheets/" and "token=" both in the URI. The first clause just
    identifies the endpoint (no specific param); the second should resolve
    to the actual query parameter name and its value."""
    import attack
    data = b"GET /api/sheets/abc123?token=7da31352 HTTP/1.1\r\nHost: x\r\n\r\n"
    clauses = [
        (b"/api/sheets/", "contains", "uri"),
        (b"token=", "contains", "uri"),
    ]
    results = attack.locate_vulnerable_input(data, clauses)
    locations = {r["location"]: r["value"] for r in results}
    assert locations["URI path"] == "/api/sheets/abc123"
    assert locations['query parameter "token"'] == "7da31352"


def test_locate_vulnerable_input_does_not_confuse_cookie_with_query_param():
    """Regression guard for the Cookie/token collision bug: a Cookie header
    containing "token=" in its own value must never be reported as if it
    were the query parameter — buffer scoping must keep these separate."""
    import attack
    data = (
        b"GET /api/sheets/abc123?token=7da31352 HTTP/1.1\r\n"
        b"Host: x\r\nCookie: auth-token=deadbeef\r\n\r\n"
    )
    clauses = [(b"token=", "contains", "uri")]
    results = attack.locate_vulnerable_input(data, clauses)
    assert len(results) == 1
    assert results[0]["location"] == 'query parameter "token"'
    assert results[0]["value"] == "7da31352"


def test_locate_vulnerable_input_matches_multibyte_pattern_consistently():
    """The pattern (from a Suricata content clause, decoded latin-1 in
    attack.py) and the haystack it's searched against must use the same
    encoding — both come from the same raw byte source. A 2-byte UTF-8
    sequence (e.g. the "é" in a query value) decodes to ONE char under
    utf-8 but TWO chars under latin-1; mixing the two would make an
    identical byte sequence compare unequal and silently fail to pinpoint
    the field."""
    import attack
    # b"\xc3\xa9" is "é" encoded as UTF-8, and also the exact bytes a
    # Suricata content clause captured from the wire would contain.
    data = b"GET /api/users?name=jos\xc3\xa9 HTTP/1.1\r\nHost: x\r\n\r\n"
    clauses = [(b"\xc3\xa9", "contains", "uri")]
    results = attack.locate_vulnerable_input(data, clauses)
    assert len(results) == 1
    assert results[0]["location"] == 'query parameter "name"'


def test_locate_vulnerable_input_pinpoints_json_body_field():
    import attack
    data = (
        b'POST /api/signup HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n\r\n'
        b'{"username": "admin", "role": "superuser"}'
    )
    clauses = [(b"superuser", "contains", "request_body")]
    results = attack.locate_vulnerable_input(data, clauses)
    assert results == [{"buffer": "request_body", "location": 'body field "role"', "value": "superuser"}]


def test_locate_vulnerable_input_pinpoints_nested_json_field():
    import attack
    data = (
        b'POST /api/x HTTP/1.1\r\nHost: y\r\n\r\n'
        b'{"user": {"@type": "com.sun.rowset.JdbcRowSetImpl"}}'
    )
    clauses = [(b"jdbcrowsetimpl", "contains", "request_body")]
    results = attack.locate_vulnerable_input(data, clauses)
    assert results[0]["location"] == 'body field "user.@type"'


def test_locate_vulnerable_input_pinpoints_form_body_field():
    import attack
    data = (
        b'POST /api/login HTTP/1.1\r\nHost: y\r\n'
        b'Content-Type: application/x-www-form-urlencoded\r\n\r\n'
        b'username=admin&password=or+1=1'
    )
    clauses = [(b"or 1=1", "contains", "request_body")]
    results = attack.locate_vulnerable_input(data, clauses)
    assert results[0]["location"] == 'body field "password"'


def test_locate_vulnerable_input_pinpoints_specific_cookie():
    import attack
    data = b"GET /x HTTP/1.1\r\nHost: y\r\nCookie: session=abc; role=admin\r\n\r\n"
    clauses = [(b"admin", "contains", "cookie")]
    results = attack.locate_vulnerable_input(data, clauses)
    assert results[0]["location"] == 'cookie "role"'
    assert results[0]["value"] == "admin"


def test_locate_vulnerable_input_falls_back_to_generic_location_when_unpinpointable():
    """A pkt-buffer clause (no sticky buffer active) can't be narrowed to a
    specific field — still reports SOMETHING rather than nothing."""
    import attack
    data = b"raw non-http bytes with jndi: inside them"
    clauses = [(b"jndi:", "contains", "pkt")]
    results = attack.locate_vulnerable_input(data, clauses)
    assert results == [{
        "buffer": "pkt", "location": "request (not narrowed to a specific field)", "value": None,
    }]


def test_locate_vulnerable_input_skips_method_clauses():
    import attack
    data = b"GET /x HTTP/1.1\r\nHost: y\r\n\r\n"
    clauses = [(b"get", "contains", "method")]
    assert attack.locate_vulnerable_input(data, clauses) == []


def test_locate_vulnerable_input_deduplicates_identical_locations():
    import attack
    data = b"GET /api/x?a=jndi:ldap HTTP/1.1\r\nHost: y\r\n\r\n"
    clauses = [(b"jndi:", "contains", "uri"), (b"ldap", "contains", "uri")]
    results = attack.locate_vulnerable_input(data, clauses)
    # Both clauses resolve to the same query parameter "a" — reported once.
    assert len(results) == 1
    assert results[0]["location"] == 'query parameter "a"'


def test_locate_vulnerable_input_truncates_long_values():
    import attack
    long_value = "x" * 500
    data = f"GET /a?q={long_value} HTTP/1.1\r\nHost: y\r\n\r\n".encode()
    clauses = [(b"xxxx", "contains", "uri")]
    results = attack.locate_vulnerable_input(data, clauses)
    assert len(results[0]["value"]) <= 301  # 300 chars + the truncation marker
    assert results[0]["value"].endswith("…")
