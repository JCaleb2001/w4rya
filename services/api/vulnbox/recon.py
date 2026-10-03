"""Service inventory: which service directories exist on the vulnbox and which
ports their containers publish. Read-only on the box.

A container belongs to a service directory when its docker compose working
directory is that directory (or below it — a compose file in a subfolder).
Ports in the game range (9000-9999) are what other teams and the checker hit;
those are the ones worth importing into /config → services.
"""

from __future__ import annotations

import re

from . import config, keys, ssh

# "0.0.0.0:9001->80/tcp", ":::9001->80/tcp", "0.0.0.0:9100-9101->8000-8001/tcp"
_HOST_PORT_RE = re.compile(r":(\d+)(?:-(\d+))?->")
# A published range is expanded to individual ports; cap it so one silly
# mapping can't flood the result (or /config).
MAX_RANGE_PORTS = 32


def _host_ports(ports_field: str) -> list[int]:
    found: set[int] = set()
    for m in _HOST_PORT_RE.finditer(ports_field or ""):
        lo = int(m.group(1))
        hi = int(m.group(2)) if m.group(2) else lo
        for p in range(lo, min(hi, lo + MAX_RANGE_PORTS - 1) + 1):
            found.add(p)
    return sorted(found)


def _is_game_port(port: int) -> bool:
    return config.GAME_PORT_MIN <= port <= config.GAME_PORT_MAX


def parse(stdout: str) -> dict:
    """Split the remote script's tab-separated records by kind."""
    dirs: list[str] = []
    containers: list[dict] = []
    notes: list[str] = []
    for line in stdout.splitlines():
        parts = line.split("\t")
        kind = parts[0]
        if kind == "DIR" and len(parts) >= 2:
            dirs.append(parts[1])
        elif kind == "CTR" and len(parts) >= 5:
            containers.append({
                "name": parts[1],
                "ports": _host_ports(parts[2]),
                "image": parts[3],
                "workdir": parts[4],
            })
        elif kind == "NOTE" and len(parts) >= 2:
            notes.append(parts[1])
    return {"dirs": dirs, "containers": containers, "notes": notes}


def build(parsed: dict, services_path: str) -> dict:
    """Join directories and containers into one row per service."""
    root = services_path.rstrip("/")
    notes = list(parsed["notes"])
    services: list[dict] = []
    claimed: set[str] = set()

    for name in parsed["dirs"]:
        if not config.is_valid_service_name(name):
            notes.append(f"skipped unsafe directory name: {name!r}")
            continue
        svc_dir = f"{root}/{name}"
        mine = [
            c for c in parsed["containers"]
            if c["workdir"] == svc_dir or c["workdir"].startswith(svc_dir + "/")
        ]
        claimed.update(c["name"] for c in mine)
        ports = sorted({p for c in mine for p in c["ports"]})
        services.append({
            "name": name,
            "ports": ports,
            "game_ports": [p for p in ports if _is_game_port(p)],
            "containers": [
                {"name": c["name"], "image": c["image"], "ports": c["ports"]} for c in mine
            ],
        })

    stray = [c["name"] for c in parsed["containers"] if c["name"] not in claimed]
    if stray:
        notes.append(
            f"{len(stray)} running container(s) not under {root}: {', '.join(stray)}"
        )
    return {"services": services, "notes": notes}


def to_config_services(services: list[dict], host: str) -> list[dict]:
    """Recon rows → /config services entries, one per game port."""
    return [
        {"name": s["name"], "ip": host, "port": p, "notes": "imported from recon"}
        for s in services
        for p in s["game_ports"]
    ]


def merge_services(existing: list[dict], imported: list[dict]) -> tuple[list[dict], int, int]:
    """Upsert by (ip, port). Never deletes: entries recon didn't see stay put.
    Returns (merged, added, updated)."""
    index = {(e.get("ip"), e.get("port")): i for i, e in enumerate(existing)}
    merged = [dict(e) for e in existing]
    added = updated = 0
    for entry in imported:
        key = (entry["ip"], entry["port"])
        if key in index:
            merged[index[key]] = dict(entry)
            updated += 1
        else:
            index[key] = len(merged)
            merged.append(dict(entry))
            added += 1
    return merged, added, updated


def run(target: config.Target) -> dict:
    """Inventory the vulnbox. Raises RuntimeError with a UI-ready message."""
    if not keys.status().get("exists"):
        raise RuntimeError("no key yet — generate one and submit it to the platform first")
    proc = ssh.run_remote_script(
        "recon", [target.services_path],
        host=target.host, port=target.port, user=target.user,
    )
    if proc.returncode != 0:
        raise RuntimeError(ssh.describe_failure(proc))
    return build(parse(proc.stdout), target.services_path)
