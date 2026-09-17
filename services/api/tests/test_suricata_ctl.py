"""Tests for suricata_ctl.reload_rules()'s cross-process coalescing.

A reload against a large ruleset can take several seconds; several gunicorn
workers (separate processes) triggering one at nearly the same time must not
each independently block on their own socket call — see reload_rules's
docstring. These tests stub out the actual socket call and drive the file
lock/state directly, so they need no real Suricata socket.
"""

from __future__ import annotations

import fcntl
import os


def _make_rules_file(tmp_path, monkeypatch, suricata_ctl, content="alert tcp any any -> any any (msg:\"x\"; sid:1;)\n"):
    """Points suricata_ctl at a real on-disk rules file so
    `_rules_file_version()` (an mtime fingerprint) has something to read."""
    path = tmp_path / "suricata.rules"
    path.write_text(content)
    monkeypatch.setattr(suricata_ctl._rules, "RULES_FILE", str(path))
    return path


def test_reload_rules_calls_send_command_when_no_reload_in_flight(monkeypatch, tmp_path):
    import suricata_ctl

    monkeypatch.setattr(suricata_ctl, "_RELOAD_LOCK_PATH", str(tmp_path / "reload.lock"))
    monkeypatch.setattr(suricata_ctl, "_RELOAD_STATE_PATH", str(tmp_path / "reload.state"))
    _make_rules_file(tmp_path, monkeypatch, suricata_ctl)

    calls = []
    monkeypatch.setattr(suricata_ctl, "_send_command", lambda cmd: calls.append(cmd) or {"return": "OK"})

    result = suricata_ctl.reload_rules()
    assert result == {"return": "OK"}
    assert calls == [{"command": "reload-rules"}]


def test_reload_rules_skips_a_second_call_already_covered_by_a_finished_one(monkeypatch, tmp_path):
    """Simulates worker B asking for a reload while worker A already reloaded
    exactly the rules file content that's on disk right now — B's request is
    already satisfied by A's reload and must not trigger a second real one."""
    import suricata_ctl

    state_path = tmp_path / "reload.state"
    monkeypatch.setattr(suricata_ctl, "_RELOAD_LOCK_PATH", str(tmp_path / "reload.lock"))
    monkeypatch.setattr(suricata_ctl, "_RELOAD_STATE_PATH", str(state_path))
    _make_rules_file(tmp_path, monkeypatch, suricata_ctl)

    # Worker A's reload already covered the file exactly as it is on disk now.
    suricata_ctl._write_reload_state({
        "reloaded_version": suricata_ctl._rules_file_version(),
        "result": {"return": "OK", "message": "from worker A"},
    })

    calls = []
    monkeypatch.setattr(suricata_ctl, "_send_command", lambda cmd: calls.append(cmd) or {"return": "OK", "message": "fresh"})

    result = suricata_ctl.reload_rules()
    assert result == {"return": "OK", "message": "from worker A"}
    assert calls == []  # never re-triggered


def test_reload_rules_triggers_a_new_reload_if_file_changed_since_last_one(monkeypatch, tmp_path):
    """The recorded reload covers an mtime that no longer matches the file on
    disk (an edit landed after that reload was snapshotted) — must not
    coalesce into a reload that predates the edit."""
    import suricata_ctl

    state_path = tmp_path / "reload.state"
    monkeypatch.setattr(suricata_ctl, "_RELOAD_LOCK_PATH", str(tmp_path / "reload.lock"))
    monkeypatch.setattr(suricata_ctl, "_RELOAD_STATE_PATH", str(state_path))
    _make_rules_file(tmp_path, monkeypatch, suricata_ctl)

    suricata_ctl._write_reload_state({
        "reloaded_version": -1,  # stands in for "some earlier version of the file"
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


def test_reload_rules_nonblocking_returns_pending_when_lock_already_held(monkeypatch, tmp_path):
    """The high-frequency auto-reload-on-save path (blocking=False) must not
    tie up a gunicorn worker waiting on a reload another worker is already
    running — it should return immediately instead."""
    import suricata_ctl

    lock_path = str(tmp_path / "reload.lock")
    monkeypatch.setattr(suricata_ctl, "_RELOAD_LOCK_PATH", lock_path)
    monkeypatch.setattr(suricata_ctl, "_RELOAD_STATE_PATH", str(tmp_path / "reload.state"))
    _make_rules_file(tmp_path, monkeypatch, suricata_ctl)

    # Simulate another worker (a separate open file description on the same
    # lock file — flock() treats these independently even within one process).
    other_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o666)
    fcntl.flock(other_fd, fcntl.LOCK_EX)
    try:
        calls = []
        monkeypatch.setattr(suricata_ctl, "_send_command", lambda cmd: calls.append(cmd) or {"return": "OK"})
        result = suricata_ctl.reload_rules(blocking=False)
        assert result == {"return": "PENDING", "message": "reload already in progress"}
        assert calls == []
    finally:
        fcntl.flock(other_fd, fcntl.LOCK_UN)
        os.close(other_fd)


def test_reload_rules_blocking_manual_route_default_unaffected(monkeypatch, tmp_path):
    """The manual '/rules/reload' route relies on the blocking=True default —
    guard the signature so that default can't silently flip."""
    import inspect
    import suricata_ctl

    assert inspect.signature(suricata_ctl.reload_rules).parameters["blocking"].default is True
