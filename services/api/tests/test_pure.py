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
