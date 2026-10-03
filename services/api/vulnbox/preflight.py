"""Read-only readiness checklist for the vulnbox. Creates nothing.

Checks run in dependency order and stop at the first broken link, so the
report always names the *actual* problem — "VPN down" is never reported as
"ssh refused our key". Rule shared with recon/backup: no key, no socket.
"""

from __future__ import annotations

from . import config, keys, ssh

# Order is the dependency chain shown in the UI.
CHECKS = ("key", "reachable", "ssh_auth", "services_path", "git", "docker")
_REMOTE_CHECKS = ("services_path", "git", "docker")


def _check(name: str, status: str, detail: str) -> dict:
    return {"name": name, "status": status, "detail": detail}


def _skip_from(results: list[dict], start: str, why: str) -> list[dict]:
    """Mark every check from `start` onwards as skipped."""
    for name in CHECKS[CHECKS.index(start):]:
        results.append(_check(name, "skipped", why))
    return results


def parse(stdout: str) -> dict:
    """`CHECK <TAB> name <TAB> ok|fail <TAB> detail` lines → {name: check}."""
    found: dict = {}
    for line in stdout.splitlines():
        parts = line.split("\t")
        if len(parts) == 4 and parts[0] == "CHECK" and parts[1] in _REMOTE_CHECKS:
            status = "ok" if parts[2] == "ok" else "fail"
            found[parts[1]] = _check(parts[1], status, parts[3])
    return found


def run(target: config.Target) -> list[dict]:
    results: list[dict] = []

    if not keys.status().get("exists"):
        results.append(_check("key", "fail", "no key yet — generate one and submit it to the platform"))
        return _skip_from(results, "reachable", "skipped — no key")
    results.append(_check("key", "ok", "key present"))

    if not ssh.tcp_reachable(target.host, target.port):
        results.append(_check(
            "reachable", "fail",
            f"cannot reach {target.host}:{target.port} — is the game VPN up?"))
        return _skip_from(results, "ssh_auth", "skipped — host unreachable")
    results.append(_check("reachable", "ok", f"{target.host}:{target.port} is reachable"))

    proc = ssh.run_remote_script(
        "preflight", [target.services_path],
        host=target.host, port=target.port, user=target.user,
    )
    if proc.returncode != 0:
        results.append(_check("ssh_auth", "fail", ssh.describe_failure(proc)))
        return _skip_from(results, "services_path", "skipped — ssh failed")
    results.append(_check("ssh_auth", "ok", f"logged in as {target.user}"))

    remote = parse(proc.stdout)
    for name in _REMOTE_CHECKS:
        # A check missing from the output is a failure, never a silent pass.
        results.append(remote.get(name) or _check(name, "fail", "no answer from the vulnbox"))
    return results
