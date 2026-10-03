"""Preflight: read-only checklist. The key point under test is that each kind
of failure is reported as *that* failure — and that with no key, nothing touches
the network at all."""

import subprocess
from pathlib import Path

import pytest

from vulnbox import config as vconfig
from vulnbox import keys, preflight, ssh

TARGET = vconfig.Target(host="192.0.2.10", port=22, user="root", services_path="/root/services")


def by_name(checks):
    return {c["name"]: c for c in checks}


@pytest.fixture
def no_network(monkeypatch):
    """Fail the test if anything tries to open a socket or run ssh."""
    def boom(*a, **k):
        raise AssertionError("network/ssh used when it must not be")
    monkeypatch.setattr(ssh, "tcp_reachable", boom)
    monkeypatch.setattr(ssh, "run_remote_script", boom)


def test_no_key_skips_everything_and_opens_no_socket(vbox_dir, no_network):
    checks = by_name(preflight.run(TARGET))
    assert checks["key"]["status"] == "fail"
    for name in ("reachable", "ssh_auth", "services_path", "git", "docker"):
        assert checks[name]["status"] == "skipped"


def test_unreachable_host_is_reported_as_such(vbox_dir, monkeypatch):
    keys.generate()
    monkeypatch.setattr(ssh, "tcp_reachable", lambda *a, **k: False)
    monkeypatch.setattr(ssh, "run_remote_script",
                        lambda *a, **k: pytest.fail("ssh must not run when unreachable"))
    checks = by_name(preflight.run(TARGET))
    assert checks["key"]["status"] == "ok"
    assert checks["reachable"]["status"] == "fail"
    assert "VPN" in checks["reachable"]["detail"]
    assert checks["ssh_auth"]["status"] == "skipped"


def test_auth_failure_is_distinguished(vbox_dir, monkeypatch):
    keys.generate()
    monkeypatch.setattr(ssh, "tcp_reachable", lambda *a, **k: True)
    monkeypatch.setattr(
        ssh, "run_remote_script",
        lambda *a, **k: subprocess.CompletedProcess(
            [], 255, stdout="", stderr="root@192.0.2.10: Permission denied (publickey)."),
    )
    checks = by_name(preflight.run(TARGET))
    assert checks["reachable"]["status"] == "ok"
    assert checks["ssh_auth"]["status"] == "fail"
    assert "platform" in checks["ssh_auth"]["detail"]
    assert checks["services_path"]["status"] == "skipped"


def test_all_green_parses_remote_checks(vbox_dir, monkeypatch):
    keys.generate()
    monkeypatch.setattr(ssh, "tcp_reachable", lambda *a, **k: True)
    out = (
        "CHECK\tservices_path\tok\t/root/services (3 service dirs)\n"
        "CHECK\tgit\tok\tgit version 2.39.5\n"
        "CHECK\tdocker\tfail\tdocker is not installed (recon cannot map ports)\n"
    )
    monkeypatch.setattr(
        ssh, "run_remote_script",
        lambda *a, **k: subprocess.CompletedProcess([], 0, stdout=out, stderr=""),
    )
    checks = by_name(preflight.run(TARGET))
    assert checks["ssh_auth"]["status"] == "ok"
    assert checks["services_path"]["status"] == "ok"
    assert checks["git"]["status"] == "ok"
    assert checks["docker"]["status"] == "fail"


def test_missing_remote_line_is_a_failure_not_a_pass(vbox_dir, monkeypatch):
    keys.generate()
    monkeypatch.setattr(ssh, "tcp_reachable", lambda *a, **k: True)
    monkeypatch.setattr(
        ssh, "run_remote_script",
        lambda *a, **k: subprocess.CompletedProcess([], 0, stdout="garbage\n", stderr=""),
    )
    checks = by_name(preflight.run(TARGET))
    assert checks["git"]["status"] == "fail"


def test_preflight_script_runs_for_real_locally(tmp_path):
    """Execute the actual remote script with bash (no ssh) to prove its
    output format matches what the parser expects."""
    services = tmp_path / "services"
    (services / "web").mkdir(parents=True)
    script = Path(preflight.__file__).parent / "remote" / "preflight.sh"
    proc = subprocess.run(["bash", str(script), str(services)],
                          capture_output=True, text=True, timeout=20)
    assert proc.returncode == 0
    parsed = preflight.parse(proc.stdout)
    assert parsed["services_path"]["status"] == "ok"
    assert "1 service dirs" in parsed["services_path"]["detail"]
    assert parsed["git"]["status"] == "ok"
