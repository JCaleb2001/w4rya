"""SSH command construction and the remote-script runner. No real network:
subprocess is faked, and we assert on how it would be invoked."""

import subprocess

import pytest

from vulnbox import ssh
from vulnbox import config as vconfig


def test_ssh_argv_has_hardening_and_no_insecure_hostkey(vbox_dir):
    argv = ssh.ssh_argv("192.0.2.10", 22, "root")
    joined = " ".join(argv)
    assert argv[0] == "ssh"
    assert "BatchMode=yes" in joined
    assert "IdentitiesOnly=yes" in joined
    assert "StrictHostKeyChecking=accept-new" in joined
    assert "ConnectTimeout=" in joined
    assert "root@192.0.2.10" in argv
    # the insecure patterns from the pasted script must never appear
    assert "StrictHostKeyChecking=no" not in joined
    assert "UserKnownHostsFile=/dev/null" not in joined
    # key + known_hosts point into our data dir
    assert str(vconfig.private_key_path()) in argv
    assert str(vconfig.known_hosts_path()) in joined


def test_ssh_argv_sets_port(vbox_dir):
    argv = ssh.ssh_argv("h", 2222, "root")
    assert "-p" in argv and "2222" in argv


def test_run_remote_script_rejects_unknown_name(vbox_dir, monkeypatch):
    called = False

    def fake_run(*a, **k):
        nonlocal called
        called = True
    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(ValueError):
        ssh.run_remote_script("../etc/passwd", host="h", port=22, user="root")
    assert called is False


def test_run_remote_script_builds_bash_stdin(vbox_dir, monkeypatch):
    captured = {}

    def fake_run(argv, **kw):
        captured["argv"] = argv
        captured["input"] = kw.get("input")
        return subprocess.CompletedProcess(argv, 0, stdout="OK\n", stderr="")
    monkeypatch.setattr(subprocess, "run", fake_run)

    res = ssh.run_remote_script("recon", ["/root/services"], host="192.0.2.10", port=22, user="root")
    assert res.returncode == 0
    # script delivered on stdin, remote command runs bash -s with the arg quoted
    assert "bash -s" in captured["argv"][-1]
    assert "/root/services" in captured["argv"][-1]
    assert captured["input"]  # the script text
    assert "#!/" in captured["input"] or "set -" in captured["input"]


def test_run_remote_script_quotes_hostile_args(vbox_dir, monkeypatch):
    captured = {}

    def fake_run(argv, **kw):
        captured["argv"] = argv
        return subprocess.CompletedProcess(argv, 0, "", "")
    monkeypatch.setattr(subprocess, "run", fake_run)

    # an argument with shell metacharacters must arrive single-quoted, so the
    # remote shell treats it as one literal word, never as a command
    ssh.run_remote_script("backup", ["/root/my services; reboot"], host="h", port=22, user="root")
    remote = captured["argv"][-1]
    assert "'/root/my services; reboot'" in remote


def test_tcp_reachable_false_for_dead_port(vbox_dir):
    # 127.0.0.1:1 is not listening; must return False fast, not raise
    assert ssh.tcp_reachable("127.0.0.1", 1, timeout=0.3) is False


def test_ssh_argv_ends_options_before_the_destination(vbox_dir):
    argv = ssh.ssh_argv("192.0.2.10", 22, "root")
    assert argv[-2:] == ["--", "root@192.0.2.10"]


def test_run_survives_output_that_is_not_utf8():
    # a filename on the box can hold any bytes; one must not kill the job
    proc = ssh.run(["bash", "-c", r"printf 'BIG\tsvc\tcaf\xe9.bin\t1\n'"])
    assert proc.returncode == 0
    assert "�" in proc.stdout


def test_timeout_message_does_not_always_blame_the_vpn():
    proc = subprocess.CompletedProcess([], 124, "", "timed out after 900s")
    msg = ssh.describe_failure(proc)
    assert "timed out after 900s" in msg
    assert "retry" in msg
