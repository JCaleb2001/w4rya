"""Git baseline + snapshots of every service on the vulnbox, mirrored locally.

Two halves:

1. Remote (`remote/backup.sh`, piped over ssh): commit each service directory
   into its own bare repo under ~/.w4rya-backups/<service>.git on the box. The
   first run is the baseline; later runs commit only real changes.
2. Local: clone (first time) or fast-forward pull each repo into
   `vulnbox-data/backups/<service>/`, so the team can read and diff the code
   on the laptop without touching the vulnbox.

Local git runs as root inside the container over a host bind mount, so it
passes `-c safe.directory=*` (honored from the command line since git 2.38;
the api image ships 2.39) and hands the tree back to the directory's owner
afterwards — the same "root writes, chown to owner" rule as user_store.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Optional

from . import config, keys, ssh

# Relative to the remote user's home: `user@host:.w4rya-backups/x.git` is
# scp-style and resolves under $HOME, matching the script's $HOME/.w4rya-backups.
REMOTE_ROOT = ".w4rya-backups"


def parse(stdout: str) -> dict:
    """SVC / BIG / NEST / FATAL records → {fatal, services:[...]}."""
    fatal: Optional[str] = None
    services: list[dict] = []
    skipped: dict[str, list[dict]] = {}
    for line in stdout.splitlines():
        parts = line.split("\t")
        if parts[0] == "FATAL" and len(parts) >= 2:
            fatal = parts[1]
        elif parts[0] == "BIG" and len(parts) >= 4:
            size = int(parts[3]) if parts[3].isdigit() else 0
            skipped.setdefault(parts[1], []).append(
                {"path": parts[2], "bytes": size, "reason": "too large"})
        elif parts[0] == "NEST" and len(parts) >= 3:
            skipped.setdefault(parts[1], []).append(
                {"path": parts[2], "bytes": 0, "reason": "nested git repository"})
        elif parts[0] == "SVC" and len(parts) >= 6:
            services.append({
                "name": parts[1],
                "status": parts[2],
                "commit": parts[3],
                "files": int(parts[4]) if parts[4].strip().isdigit() else 0,
                "detail": parts[5],
            })
    for s in services:
        s["skipped"] = skipped.get(s["name"], [])
    return {"fatal": fatal, "services": services}


def remote_url(target: config.Target, name: str) -> str:
    # scp-style git URLs need an IPv6 literal bracketed, or its colons read as
    # the host/path separator.
    host = f"[{target.host}]" if config.is_ipv6(target.host) else target.host
    return f"{target.user}@{host}:{REMOTE_ROOT}/{name}.git"


def _git(args: list[str], target: config.Target, cwd: Optional[Path] = None,
         timeout: int = config.BACKUP_TIMEOUT):
    env = dict(os.environ)
    env["GIT_SSH_COMMAND"] = ssh.git_ssh_command(target.port)
    env["GIT_TERMINAL_PROMPT"] = "0"  # never block a background job on a prompt
    return ssh.run(["git", "-c", "safe.directory=*", *args], env=env,
                   cwd=str(cwd) if cwd else None, timeout=timeout)


def _own_tree(root: Path) -> None:
    """Hand a clone, written as root, to the data directory's owner."""
    config.own(root)
    for dirpath, dirnames, filenames in os.walk(root):
        for name in dirnames + filenames:
            config.own(os.path.join(dirpath, name))


def _sync_local(target: config.Target, name: str, commit: str) -> tuple[str, str]:
    """Bring the local mirror of one service to the box's `commit`.
    Returns (local_status, detail)."""
    dest = config.backups_dir() / name
    if (dest / ".git").is_dir():
        # Compare with the mirror itself, not with the box's "unchanged": a
        # pull that failed last time leaves the mirror behind a snapshot the
        # box no longer reports as new.
        head = _git(["rev-parse", "HEAD"], target, cwd=dest)
        if head.returncode == 0 and head.stdout.strip() == commit:
            return "up to date", ""
        # Pull from wherever the box is now (vm_ip or the ssh user may have
        # changed since the first clone).
        _git(["remote", "set-url", "origin", remote_url(target, name)], target, cwd=dest)
        proc = _git(["pull", "--ff-only", "-q"], target, cwd=dest)
        if proc.returncode != 0:
            return "error", ssh.describe_failure(proc)
        _own_tree(dest)
        return "pulled", ""
    if dest.exists():
        return "error", f"{dest.name} is in the backups directory but is not a git clone — move it away"

    # Clone beside the destination and rename into place, so a clone cut off
    # half-way (timeout, VPN drop) never leaves a directory that later runs
    # mistake for a mirror.
    config.ensure_dir(config.backups_dir())
    tmp = config.backups_dir() / f".{name}.cloning"
    shutil.rmtree(tmp, ignore_errors=True)
    proc = _git(["clone", "-q", remote_url(target, name), str(tmp)], target)
    if proc.returncode != 0:
        shutil.rmtree(tmp, ignore_errors=True)
        return "error", ssh.describe_failure(proc)
    os.rename(tmp, dest)
    _own_tree(dest)
    return "cloned", ""


def run(target: config.Target) -> dict:
    """Snapshot every service on the box, then mirror it locally.
    Raises RuntimeError with a UI-ready message when nothing could run."""
    if not keys.status().get("exists"):
        raise RuntimeError("no key yet — generate one and submit it to the platform first")
    proc = ssh.run_remote_script(
        "backup", [target.services_path, str(config.MAX_FILE_BYTES)],
        host=target.host, port=target.port, user=target.user,
        timeout=config.BACKUP_TIMEOUT,
    )
    if proc.returncode != 0:
        raise RuntimeError(ssh.describe_failure(proc))

    result = parse(proc.stdout)
    for svc in result["services"]:
        if svc["status"] == "error" or not config.is_valid_service_name(svc["name"]):
            svc["local"], svc["local_detail"] = "skipped", ""
            continue
        svc["local"], svc["local_detail"] = _sync_local(target, svc["name"], svc["commit"])
    return result
