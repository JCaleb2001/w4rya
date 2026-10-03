"""Backup: the real remote script (run locally with bash) and a real local git
clone/pull. Only the SSH hop is faked — the script runs in a tmp HOME, and the
clone URL points at the resulting bare repo on disk."""

import subprocess
from pathlib import Path

import pytest

from vulnbox import backup, keys, ssh
from vulnbox import config as vconfig

SCRIPT = Path(backup.__file__).parent / "remote" / "backup.sh"


@pytest.fixture
def box(tmp_path):
    """A fake vulnbox: a services dir and a HOME for ~/.w4rya-backups."""
    services = tmp_path / "box" / "services"
    home = tmp_path / "box" / "home"
    (services / "web").mkdir(parents=True)
    (services / "web" / "index.html").write_text("<h1>v1</h1>\n")
    (services / "api").mkdir()
    (services / "api" / "app.py").write_text("print('hi')\n")
    home.mkdir()
    return {"services": services, "home": home, "root": home / ".w4rya-backups"}


def run_script(box, max_bytes=1_000_000):
    proc = subprocess.run(
        ["bash", str(SCRIPT), str(box["services"]), str(max_bytes)],
        capture_output=True, text=True, timeout=60,
        env={"HOME": str(box["home"]), "PATH": "/usr/bin:/bin:/usr/local/bin"},
    )
    assert proc.returncode == 0, proc.stderr
    return backup.parse(proc.stdout)


def rows(parsed):
    return {s["name"]: s for s in parsed["services"]}


# --- the remote script itself ----------------------------------------------

def test_first_run_is_baseline_in_a_bare_repo_outside_the_service(box):
    r = rows(run_script(box))
    assert r["web"]["status"] == "created"
    assert r["web"]["commit"]
    assert r["web"]["files"] == 1
    # the whole point: no .git inside the served directory
    assert not (box["services"] / "web" / ".git").exists()
    assert (box["root"] / "web.git" / "HEAD").exists()


def test_second_run_without_changes_is_unchanged(box):
    run_script(box)
    r = rows(run_script(box))
    assert r["web"]["status"] == "unchanged"


def test_change_creates_a_new_snapshot(box):
    first = rows(run_script(box))["web"]["commit"]
    (box["services"] / "web" / "index.html").write_text("<h1>v2 patched</h1>\n")
    r = rows(run_script(box))
    assert r["web"]["status"] == "updated"
    assert r["web"]["commit"] != first


def test_oversized_files_are_skipped_and_reported(box):
    (box["services"] / "api" / "dump.bin").write_bytes(b"x" * 5000)
    parsed = run_script(box, max_bytes=1000)
    r = rows(parsed)
    assert r["api"]["files"] == 1  # app.py only
    assert {b["path"] for b in r["api"]["skipped"]} == {"dump.bin"}
    tracked = subprocess.run(
        ["git", "--git-dir", str(box["root"] / "api.git"), "ls-tree", "-r", "--name-only", "HEAD"],
        capture_output=True, text=True,
    ).stdout.split()
    assert tracked == ["app.py"]


def test_unsafe_directory_name_is_refused(box):
    (box["services"] / "bad name").mkdir()
    r = rows(run_script(box))
    assert r["bad name"]["status"] == "error"
    assert "unsafe" in r["bad name"]["detail"]
    assert not (box["root"] / "bad name.git").exists()


def test_fatal_when_services_path_missing(box, tmp_path):
    box = dict(box, services=tmp_path / "nope")
    parsed = run_script(box)
    assert parsed["fatal"] and "not found" in parsed["fatal"]


# --- run(): remote script + local clone/pull --------------------------------

@pytest.fixture
def wired(box, vbox_dir, monkeypatch):
    """backup.run() with the ssh hop replaced by a local bash run, and the
    clone URL pointed at the local bare repos."""
    keys.generate()

    def fake_remote(name, args, **kw):
        return subprocess.run(
            ["bash", str(SCRIPT), *args], capture_output=True, text=True, timeout=60,
            env={"HOME": str(box["home"]), "PATH": "/usr/bin:/bin:/usr/local/bin"},
        )
    monkeypatch.setattr(ssh, "run_remote_script", fake_remote)
    monkeypatch.setattr(backup, "remote_url", lambda target, name: str(box["root"] / f"{name}.git"))
    target = vconfig.Target(host="10.60.3.2", port=22, user="root",
                            services_path=str(box["services"]))
    return target


def test_run_clones_then_reports_up_to_date_then_pulls(box, wired):
    out = backup.run(wired)
    assert out["fatal"] is None
    r = {s["name"]: s for s in out["services"]}
    assert r["web"]["local"] == "cloned"
    local = vconfig.backups_dir() / "web" / "index.html"
    assert local.read_text() == "<h1>v1</h1>\n"

    r = {s["name"]: s for s in backup.run(wired)["services"]}
    assert r["web"]["local"] == "up to date"

    (box["services"] / "web" / "index.html").write_text("<h1>v2</h1>\n")
    r = {s["name"]: s for s in backup.run(wired)["services"]}
    assert r["web"]["status"] == "updated"
    assert r["web"]["local"] == "pulled"
    assert local.read_text() == "<h1>v2</h1>\n"


def test_run_without_key_errors_without_ssh(vbox_dir, monkeypatch):
    monkeypatch.setattr(ssh, "run_remote_script", lambda *a, **k: pytest.fail("ssh used"))
    target = vconfig.Target(host="h", port=22, user="root", services_path="/root/services")
    with pytest.raises(RuntimeError, match="key"):
        backup.run(target)


def test_remote_url_is_relative_to_the_remote_home():
    target = vconfig.Target(host="10.60.3.2", port=22, user="root", services_path="/root/services")
    assert backup.remote_url(target, "web") == "root@10.60.3.2:.w4rya-backups/web.git"
