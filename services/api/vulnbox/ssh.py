"""SSH transport to our vulnbox.

Builds every command as an argv list — never `shell=True`, never string
interpolation into a local shell. The only place text crosses into a shell is
the *remote* `bash -s` command line, where every argument is `shlex.quote`d.

Hardening, deliberately different from the ad-hoc script this module replaces
(which used `StrictHostKeyChecking=no` + `UserKnownHostsFile=/dev/null`, i.e.
accept any host key, which lets anyone on the path impersonate the vulnbox):

- `StrictHostKeyChecking=accept-new` + our own `known_hosts`: trust on first
  use, then pin. A changed host key fails loudly; `keys.forget_host_key()` is
  the explicit escape hatch when the box is legitimately re-provisioned.
- `BatchMode=yes`: never block on a password/passphrase prompt in a
  background job.
- `IdentitiesOnly=yes`: offer only our key, not whatever an agent holds.
"""

from __future__ import annotations

import shlex
import socket
import subprocess
from pathlib import Path
from typing import Optional, Sequence

from . import config

# Scripts we are willing to run on the vulnbox, by name. Anything else is
# rejected before a process is spawned.
_REMOTE_DIR = Path(__file__).parent / "remote"
ALLOWED_SCRIPTS = frozenset({"preflight", "recon", "backup"})


def ssh_options() -> list[str]:
    return [
        "-o", "BatchMode=yes",
        "-o", "IdentitiesOnly=yes",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", f"UserKnownHostsFile={config.known_hosts_path()}",
        "-o", f"ConnectTimeout={config.CONNECT_TIMEOUT}",
        "-o", "ServerAliveInterval=15",
        "-o", "LogLevel=ERROR",
    ]


def ssh_argv(host: str, port: int, user: str) -> list[str]:
    """`ssh` up to and including the destination; append the remote command.
    `--` ends the options, so the destination can never be read as one."""
    return [
        "ssh",
        "-p", str(port),
        "-i", str(config.private_key_path()),
        *ssh_options(),
        "--",
        f"{user}@{host}",
    ]


def git_ssh_command(port: int) -> str:
    """Value for GIT_SSH_COMMAND so a local `git clone/pull` reuses the same
    key, pinned host key and hardening. git runs this through a shell, so each
    piece is quoted."""
    parts = ["ssh", "-p", str(port), "-i", str(config.private_key_path()), *ssh_options()]
    return " ".join(shlex.quote(p) for p in parts)


def _script_text(name: str) -> str:
    if name not in ALLOWED_SCRIPTS:
        raise ValueError(f"unknown remote script: {name!r}")
    return (_REMOTE_DIR / f"{name}.sh").read_text()


def run_remote_script(
    name: str,
    args: Optional[Sequence[str]] = None,
    *,
    host: str,
    port: int,
    user: str,
    timeout: int = config.RUN_TIMEOUT,
) -> subprocess.CompletedProcess:
    """Pipe `remote/<name>.sh` into `bash -s` on the vulnbox.

    Same technique as scripts/vulnbox/remote_capture.sh: nothing is installed
    on the box; the script travels on stdin. Arguments reach the script as
    "$1", "$2", ... and are shell-quoted so the remote shell sees each one as a
    single literal word.
    """
    script = _script_text(name)
    remote_cmd = "bash -s"
    if args:
        remote_cmd += " -- " + " ".join(shlex.quote(str(a)) for a in args)
    argv = ssh_argv(host, port, user) + [remote_cmd]
    return run(argv, input=script, timeout=timeout)


def run(argv: list[str], *, input: Optional[str] = None, timeout: int = config.RUN_TIMEOUT,
        env: Optional[dict] = None, cwd: Optional[str] = None) -> subprocess.CompletedProcess:
    """subprocess.run that never raises for the expected failures: a timeout
    or a missing binary come back as a CompletedProcess with a readable stderr,
    so every caller handles failure through one path (`describe_failure`)."""
    try:
        # errors="replace": the box's filenames can hold any bytes (other
        # teams pick them); one bad name must not fail the whole job.
        return subprocess.run(
            argv, input=input, capture_output=True, text=True, errors="replace",
            timeout=timeout, env=env, cwd=cwd,
        )
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(argv, 124, "", f"timed out after {timeout}s")
    except FileNotFoundError:
        return subprocess.CompletedProcess(
            argv, 127, "", f"{argv[0]} is not installed in the api container")
    finally:
        fix_known_hosts_ownership()


def fix_known_hosts_ownership() -> None:
    """ssh (running as root in the container) creates/updates known_hosts on
    the host bind mount; hand it to the data directory's owner."""
    kh = config.known_hosts_path()
    if kh.exists():
        config.own(kh)


def describe_failure(proc: subprocess.CompletedProcess) -> str:
    """Turn a failed ssh run into one actionable sentence for the UI."""
    err = (proc.stderr or "").strip()
    low = err.lower()
    if "host key verification failed" in low or "remote host identification has changed" in low:
        return ("the vulnbox host key changed — if the box was re-provisioned, "
                "use 'forget host key' and retry")
    if "permission denied" in low:
        return ("ssh refused our key — has the public key been submitted to the "
                "platform (and the box restarted with it)?")
    if "connection timed out" in low or "no route to host" in low:
        return "cannot reach the vulnbox — is the game VPN up?"
    if "connection refused" in low:
        return "the vulnbox refused the ssh connection — is sshd running on that port?"
    if proc.returncode == 124 or "timed out after" in low:
        # A long clone over a slow link times out too, so don't blame the VPN.
        return f"{err} — check the game VPN, or retry if the link is just slow"
    if proc.returncode == 127:
        return err
    tail = err.splitlines()[-1] if err else f"exit code {proc.returncode}"
    return f"ssh failed: {tail}"


def tcp_reachable(host: str, port: int, timeout: float = config.CONNECT_TIMEOUT) -> bool:
    """Can we open a TCP connection to the SSH port at all? Separates 'VPN or
    host is down' from 'SSH refused our key' in preflight."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False
