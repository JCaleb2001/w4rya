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
from pathlib import Path
from typing import Optional

from . import config, keys, ssh

# Relative to the remote user's home: `user@host:.w4rya-backups/x.git` is
# scp-style and resolves under $HOME, matching the script's $HOME/.w4rya-backups.
REMOTE_ROOT = ".w4rya-backups"


def parse(stdout: str) -> dict:
    """SVC / BIG / FATAL records → {fatal, services:[...]}."""
    fatal: Optional[str] = None
    services: list[dict] = []
    big: dict[str, list[dict]] = {}
    for line in stdout.splitlines():
        parts = line.split("\t")
        if parts[0] == "FATAL" and len(parts) >= 2:
            fatal = parts[1]
        elif parts[0] == "BIG" and len(parts) >= 4:
            size = int(parts[3]) if parts[3].isdigit() else 0
            big.setdefault(parts[1], []).append({"path": parts[2], "bytes": size})
        elif parts[0] == "SVC" and len(parts) >= 6:
            services.append({
                "name": parts[1],
                "status": parts[2],
                "commit": parts[3],
                "files": int(parts[4]) if parts[4].strip().isdigit() else 0,
                "detail": parts[5],
            })
    for s in services:
        s["skipped"] = big.get(s["name"], [])
    return {"fatal": fatal, "services": services}


def remote_url(target: config.Target, name: str) -> str:
    # scp-style git URLs need an IPv6 literal bracketed, or its colons read as
    # the host/path separator.
    host = f"[{target.host}]" if config.is_ipv6(target.host) else target.host
    return f"{target.user}@{host}:{REMOTE_ROOT}/{name}.git"


def _git(args: list[str], target: config.Target, cwd: Optional[Path] = None):
    env = dict(os.environ)
    env["GIT_SSH_COMMAND"] = ssh.git_ssh_command(target.port)
    env["GIT_TERMINAL_PROMPT"] = "0"  # never block a background job on a prompt
    return ssh.run(["git", "-c", "safe.directory=*", *args], env=env,
                   cwd=str(cwd) if cwd else None)


def _chown_tree(root: Path) -> None:
    """Give a freshly written clone back to the backups dir's owner."""
    try:
        st = config.backups_dir().stat()
    except OSError:
        return
    for dirpath, dirnames, filenames in os.walk(root):
        for name in (dirpath, *(os.path.join(dirpath, n) for n in dirnames + filenames)):
            try:
                os.lchown(name, st.st_uid, st.st_gid)
            except OSError:
                pass


def _sync_local(target: config.Target, name: str, remote_status: str) -> tuple[str, str]:
    """Clone or pull one service. Returns (local_status, detail)."""
    dest = config.backups_dir() / name
    if (dest / ".git").is_dir():
        if remote_status == "unchanged":
            return "up to date", ""
        proc = _git(["pull", "--ff-only", "-q"], target, cwd=dest)
        verb = "pulled"
    else:
        config.ensure_dir(config.backups_dir())
        proc = _git(["clone", "-q", remote_url(target, name), str(dest)], target)
        verb = "cloned"
    if proc.returncode != 0:
        return "error", ssh.describe_failure(proc)
    _chown_tree(dest)
    return verb, ""


def run(target: config.Target) -> dict:
    """Snapshot every service on the box, then mirror it locally.
    Raises RuntimeError with a UI-ready message when nothing could run."""
    if not keys.status().get("exists"):
        raise RuntimeError("no key yet — generate one and submit it to the platform first")
    proc = ssh.run_remote_script(
        "backup", [target.services_path, str(config.MAX_FILE_BYTES)],
        host=target.host, port=target.port, user=target.user,
    )
    if proc.returncode != 0:
        raise RuntimeError(ssh.describe_failure(proc))

    result = parse(proc.stdout)
    for svc in result["services"]:
        if svc["status"] == "error" or not config.is_valid_service_name(svc["name"]):
            svc["local"], svc["local_detail"] = "skipped", ""
            continue
        svc["local"], svc["local_detail"] = _sync_local(target, svc["name"], svc["status"])
    return result
