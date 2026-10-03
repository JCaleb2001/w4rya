"""Backup: the real remote script (run locally with bash) and a real local git
clone/pull. Only the SSH hop is faked — the script runs in a tmp HOME, and the
clone URL points at the resulting bare repo on disk."""

import os
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
    target = vconfig.Target(host="192.0.2.10", port=22, user="root",
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
    target = vconfig.Target(host="192.0.2.10", port=22, user="root", services_path="/root/services")
    assert backup.remote_url(target, "web") == "root@192.0.2.10:.w4rya-backups/web.git"


def test_remote_url_brackets_an_ipv6_host():
    target = vconfig.Target(host="2001:db8::2", port=22, user="root", services_path="/root/services")
    assert backup.remote_url(target, "web") == "root@[2001:db8::2]:.w4rya-backups/web.git"


# --- review fixes: what the baseline really contains ---------------------------

def tree(box, name):
    out = subprocess.run(
        ["git", "--git-dir", str(box["root"] / f"{name}.git"), "ls-tree", "-r", "HEAD"],
        capture_output=True, text=True,
    ).stdout
    return {line.split("\t", 1)[1]: line.split()[0] for line in out.splitlines()}


def test_a_tracked_file_that_grows_past_the_cap_leaves_the_snapshot(box):
    (box["services"] / "api" / "data.db").write_bytes(b"x" * 10)
    run_script(box, max_bytes=1000)
    assert "data.db" in tree(box, "api")
    (box["services"] / "api" / "data.db").write_bytes(b"x" * 5000)
    r = rows(run_script(box, max_bytes=1000))
    assert {s["path"] for s in r["api"]["skipped"]} == {"data.db"}
    assert "data.db" not in tree(box, "api")


def test_files_hidden_by_the_services_own_gitignore_are_backed_up(box):
    svc = box["services"] / "api"
    (svc / ".gitignore").write_text(".env\n*.db\n")
    (svc / ".env").write_text("SECRET=1\n")
    (svc / "state.db").write_bytes(b"db")
    run_script(box)
    assert {".env", "state.db", ".gitignore", "app.py"} <= set(tree(box, "api"))


def test_nested_git_checkouts_are_reported_not_stored_as_empty_links(box):
    lib = box["services"] / "api" / "vendor" / "lib"
    lib.mkdir(parents=True)
    (lib / "lib.py").write_text("x = 1\n")
    subprocess.run(["git", "init", "-q", str(lib)], check=True)
    r = rows(run_script(box))
    assert {"path": "vendor/lib", "bytes": 0, "reason": "nested git repository"} in r["api"]["skipped"]
    assert all(mode != "160000" for mode in tree(box, "api").values())  # no gitlink


def test_commit_is_the_full_hash(box):
    commit = rows(run_script(box))["web"]["commit"]
    assert len(commit) == 40 and int(commit, 16) >= 0


# --- review fixes: the local mirror -------------------------------------------

def git_out(cwd, *args):
    return subprocess.run(["git", "-C", str(cwd), *args], capture_output=True,
                          text=True).stdout.strip()


def test_backup_runs_with_the_long_backup_timeout(box, wired, monkeypatch):
    seen = {}
    real = ssh.run_remote_script

    def spy(name, args, **kw):
        seen["timeout"] = kw.get("timeout")
        return real(name, args, **kw)
    monkeypatch.setattr(ssh, "run_remote_script", spy)
    backup.run(wired)
    assert seen["timeout"] == vconfig.BACKUP_TIMEOUT


def test_a_failed_pull_is_retried_even_when_the_box_reports_unchanged(box, wired, monkeypatch):
    backup.run(wired)
    (box["services"] / "web" / "index.html").write_text("<h1>v2</h1>\n")
    real_git = backup._git

    def failing_pull(args, target, cwd=None, **kw):
        if args[0] == "pull":
            return subprocess.CompletedProcess(args, 1, "", "Connection timed out")
        return real_git(args, target, cwd=cwd, **kw)
    monkeypatch.setattr(backup, "_git", failing_pull)
    r = {s["name"]: s for s in backup.run(wired)["services"]}
    assert r["web"]["local"] == "error"

    monkeypatch.setattr(backup, "_git", real_git)
    r = {s["name"]: s for s in backup.run(wired)["services"]}
    assert r["web"]["status"] == "unchanged"
    assert r["web"]["local"] == "pulled"  # not "up to date": the mirror was behind
    assert (vconfig.backups_dir() / "web" / "index.html").read_text() == "<h1>v2</h1>\n"


def test_the_mirror_follows_a_changed_target(box, wired, monkeypatch, tmp_path):
    import shutil
    backup.run(wired)
    moved = tmp_path / "moved-box"
    real_remote = ssh.run_remote_script

    def remote_then_move(name, args, **kw):
        proc = real_remote(name, args, **kw)
        shutil.rmtree(moved, ignore_errors=True)
        shutil.copytree(box["root"], moved)  # the box now answers at a new address
        return proc
    monkeypatch.setattr(ssh, "run_remote_script", remote_then_move)
    monkeypatch.setattr(backup, "remote_url", lambda target, name: str(moved / f"{name}.git"))
    (box["services"] / "web" / "index.html").write_text("<h1>v3</h1>\n")
    r = {s["name"]: s for s in backup.run(wired)["services"]}
    assert r["web"]["local"] == "pulled"
    local = vconfig.backups_dir() / "web"
    assert git_out(local, "remote", "get-url", "origin") == str(moved / "web.git")


def test_an_interrupted_clone_leaves_nothing_behind(box, wired, monkeypatch):
    real_git = backup._git

    def dying_clone(args, target, cwd=None, **kw):
        if args[0] == "clone":
            Path(args[-1], ".git").mkdir(parents=True)  # half-made checkout
            return subprocess.CompletedProcess(args, 124, "", "timed out after 900s")
        return real_git(args, target, cwd=cwd, **kw)
    monkeypatch.setattr(backup, "_git", dying_clone)
    r = {s["name"]: s for s in backup.run(wired)["services"]}
    assert r["web"]["local"] == "error"
    assert not (vconfig.backups_dir() / "web").exists()
    assert not any(p.name.startswith(".") for p in vconfig.backups_dir().iterdir())

    monkeypatch.setattr(backup, "_git", real_git)
    r = {s["name"]: s for s in backup.run(wired)["services"]}
    assert r["web"]["local"] == "cloned"


@pytest.mark.skipif(os.geteuid() != 0, reason="chown to another uid needs root")
def test_clones_belong_to_the_data_dir_owner(box, wired):
    os.chown(vconfig.data_dir(), 4242, 4242)
    vconfig.init_paths()
    backup.run(wired)
    clone = vconfig.backups_dir() / "web"
    assert clone.stat().st_uid == 4242
    assert (clone / "index.html").stat().st_uid == 4242
