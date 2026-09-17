"""Tests for suricata_ctl.reload_rules()'s cross-process coalescing.

A reload against a large ruleset can take several seconds; several gunicorn
workers (separate processes) triggering one at nearly the same time must not
each independently block on their own socket call — see reload_rules's
docstring. These tests stub out the actual socket call and drive the file
lock/state directly, so they need no real Suricata socket.
"""

from __future__ import annotations

import time


def test_reload_rules_calls_send_command_when_no_reload_in_flight(monkeypatch, tmp_path):
    import suricata_ctl

    monkeypatch.setattr(suricata_ctl, "_RELOAD_LOCK_PATH", str(tmp_path / "reload.lock"))
    monkeypatch.setattr(suricata_ctl, "_RELOAD_STATE_PATH", str(tmp_path / "reload.state"))

    calls = []
    monkeypatch.setattr(suricata_ctl, "_send_command", lambda cmd: calls.append(cmd) or {"return": "OK"})

    result = suricata_ctl.reload_rules()
    assert result == {"return": "OK"}
    assert calls == [{"command": "reload-rules"}]


def test_reload_rules_skips_a_second_call_already_covered_by_a_finished_one(monkeypatch, tmp_path):
    """Simulates worker B asking for a reload while worker A's reload (which
    started before B asked) is already recorded as complete — B's request is
    already satisfied and must not trigger a second real reload."""
    import suricata_ctl

    state_path = tmp_path / "reload.state"
    monkeypatch.setattr(suricata_ctl, "_RELOAD_LOCK_PATH", str(tmp_path / "reload.lock"))
    monkeypatch.setattr(suricata_ctl, "_RELOAD_STATE_PATH", str(state_path))

    # Worker A's reload already completed in the future relative to B's request.
    suricata_ctl._write_reload_state({
        "completed_at": time.time() + 10,
        "result": {"return": "OK", "message": "from worker A"},
    })

    calls = []
    monkeypatch.setattr(suricata_ctl, "_send_command", lambda cmd: calls.append(cmd) or {"return": "OK", "message": "fresh"})

    result = suricata_ctl.reload_rules()
    assert result == {"return": "OK", "message": "from worker A"}
    assert calls == []  # never re-triggered


def test_reload_rules_triggers_a_new_reload_if_last_one_predates_this_request(monkeypatch, tmp_path):
    import suricata_ctl

    state_path = tmp_path / "reload.state"
    monkeypatch.setattr(suricata_ctl, "_RELOAD_LOCK_PATH", str(tmp_path / "reload.lock"))
    monkeypatch.setattr(suricata_ctl, "_RELOAD_STATE_PATH", str(state_path))

    suricata_ctl._write_reload_state({
        "completed_at": time.time() - 10,
        "result": {"return": "OK", "message": "stale"},
    })

    calls = []
    monkeypatch.setattr(suricata_ctl, "_send_command", lambda cmd: calls.append(cmd) or {"return": "OK", "message": "fresh"})

    result = suricata_ctl.reload_rules()
    assert result == {"return": "OK", "message": "fresh"}
    assert calls == [{"command": "reload-rules"}]


def test_reload_rules_falls_back_to_unlocked_call_without_fcntl(monkeypatch, tmp_path):
    """Non-POSIX environments (e.g. a Windows dev/test box) have no fcntl —
    reload_rules must still work, just without cross-process coalescing."""
    import suricata_ctl

    monkeypatch.setattr(suricata_ctl, "fcntl", None)
    calls = []
    monkeypatch.setattr(suricata_ctl, "_send_command", lambda cmd: calls.append(cmd) or {"return": "OK"})

    assert suricata_ctl.reload_rules() == {"return": "OK"}
    assert calls == [{"command": "reload-rules"}]
