"""Paths, limits and validators for the vulnbox module.

Everything the rest of the package needs to know about *where* things live and
*what a valid value looks like* lives here, defined once. No AI, no network —
pure configuration.

The data directory is env-driven (`W4RYA_VULNBOX_DIR`, default
`/app/vulnbox-data`) exactly like `W4RYA_USERS_FILE` / `W4RYA_RULES_FILE`, so
the test suite can redirect it at a tmp dir. Nothing here touches the
filesystem at import time; `init_paths()` (called from `webservice.create_app`)
and the lazy `ensure_dir` helper create directories on demand.
"""

from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Target:
    """Where to connect, resolved from /config once per job. Operations take
    this instead of reading app_config themselves, which keeps them pure and
    trivially testable."""
    host: str
    port: int
    user: str
    services_path: str


# --- where things live -----------------------------------------------------

def data_dir() -> Path:
    """Root of the git-ignored, bind-mounted data directory. Read fresh each
    call so a test monkeypatching the env var takes effect immediately."""
    return Path(os.environ.get("W4RYA_VULNBOX_DIR", "/app/vulnbox-data"))


def keys_dir() -> Path:
    return data_dir() / "keys"


def backups_dir() -> Path:
    return data_dir() / "backups"


def private_key_path() -> Path:
    return keys_dir() / "id_ed25519"


def public_key_path() -> Path:
    return keys_dir() / "id_ed25519.pub"


def known_hosts_path() -> Path:
    return keys_dir() / "known_hosts"


def job_path() -> Path:
    return data_dir() / "job.json"


def job_lock_path() -> Path:
    return data_dir() / "job.lock"


# --- limits ----------------------------------------------------------------

# Services are small source trees; a single file bigger than this in a backup
# is almost always a build artifact / dump / stray pcap, not source worth
# versioning. Skipped (and reported) rather than committed, so one giant file
# can't blow up the local clone or the vulnbox's disk.
MAX_FILE_BYTES = 25 * 1024 * 1024

# SSH/git must give up quickly when the VPN is down rather than hanging a whole
# background job; the game-day network is either up or it isn't.
CONNECT_TIMEOUT = 8
RUN_TIMEOUT = 120

# ECSC 2026: the game firewall only lets other teams reach the vulnbox on
# 9000-9999, so a published port in this range is a game service; anything
# else is our own tooling.
GAME_PORT_MIN = 9000
GAME_PORT_MAX = 9999

# The ECSC 2026 A/D values (handbook §6.4 + the A/D wiki), applied by the
# "ECSC 2026 defaults" button. flag_regex is the official pattern *unanchored*:
# w4rya searches for flags inside traffic, so ^...$ would never match.
# flag_lifetime counts ticks including the current one (see Corrie's
# `tick - (flagLifetime - 1)`): a flag is valid in its round + 4 more = 5.
# start_date is 2026-10-15 11:00 CEST (= 09:00 UTC).
ECSC2026_DEFAULTS = {
    "flag_regex": r"ECSC\{[A-Za-z0-9_-]{32}\}",
    "tick_length": 60000,
    "flag_lifetime": 5,
    "start_date": "2026-10-15T09:00:00Z",
}


# --- validation ------------------------------------------------------------

# A vulnbox service directory name. Deliberately strict: this name is spliced
# into remote paths and git refs, so anything outside this set (`..`, `/`, `;`,
# spaces, shell metacharacters) is rejected rather than quoted-and-hoped.
SERVICE_RE = re.compile(r"^[A-Za-z0-9._-]+$")

# SSH username charset (POSIX-portable account names).
USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")


def is_valid_service_name(name: str) -> bool:
    return bool(name) and name not in (".", "..") and SERVICE_RE.match(name) is not None


def resolve_host(team_id: str, override: str) -> str:
    """The vulnbox address to SSH into.

    An explicit `vulnbox_ip` override always wins (demo slots, self-hosting).
    Otherwise derive the ECSC game-network address `10.60.<team_id>.2` from the
    numeric team id. Raises ValueError when neither is usable — far better than
    silently SSHing at a malformed `10.60..2`.
    """
    override = (override or "").strip()
    if override:
        # Accept a bare host or an ip; validate an ip-looking value so a typo
        # fails here, not mid-connection.
        try:
            ipaddress.ip_address(override)
        except ValueError:
            if not re.match(r"^[A-Za-z0-9.-]+$", override):
                raise ValueError(f"invalid vulnbox_ip override: {override!r}")
        return override
    team_id = (team_id or "").strip()
    if not team_id.isdigit():
        raise ValueError(
            "cannot derive the vulnbox address: set team_id (a number) in "
            "/config, or set vulnbox_ip explicitly"
        )
    n = int(team_id)
    if not (0 <= n <= 255):
        raise ValueError(f"team_id {n} is out of range for 10.60.<id>.2")
    return f"10.60.{n}.2"


def validate_port(raw) -> int:
    try:
        port = int(raw)
    except (TypeError, ValueError):
        raise ValueError(f"invalid port: {raw!r}")
    if not (1 <= port <= 65535):
        raise ValueError(f"port out of range: {port}")
    return port


def validate_username(raw) -> str:
    user = str(raw or "").strip()
    if not USERNAME_RE.match(user):
        raise ValueError(f"invalid ssh username: {raw!r}")
    return user


def validate_services_path(raw) -> str:
    path = str(raw or "").strip()
    if not path.startswith("/"):
        raise ValueError("services path must be absolute (e.g. /root/services)")
    return path


def validate_host_override(raw) -> str:
    """Write-time check for the vulnbox_ip config key. Empty is allowed
    (means 'derive from team_id'); a non-empty value must be a valid ip or
    hostname."""
    value = str(raw or "").strip()
    if not value:
        return ""
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        if not re.match(r"^[A-Za-z0-9.-]+$", value):
            raise ValueError(f"invalid vulnbox_ip: {value!r}")
        return value


# --- filesystem (lazy; never at import) ------------------------------------

def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def init_paths() -> None:
    """Create the data directory tree. Called from create_app(), not import."""
    ensure_dir(keys_dir())
    ensure_dir(backups_dir())
