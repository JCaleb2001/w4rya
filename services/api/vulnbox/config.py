"""Paths, limits and validators for the vulnbox module.

Everything the rest of the package needs to know about *where* things live and
*what a valid value looks like* lives here, defined once. No AI, no network —
pure configuration.

Nothing here is specific to one A/D game. Values that differ per game (round
length, flag format, which ports are game services, ...) are settings in
/config, and named bundles of them live in `presets.py` as data.

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


# Inclusive (low, high) port ranges. Empty means "no filter".
PortRanges = tuple[tuple[int, int], ...]


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

# SSH/git must give up quickly when the game network is down rather than
# hanging a whole background job: the VPN is either up or it isn't.
CONNECT_TIMEOUT = 8
RUN_TIMEOUT = 120
# A backup moves whole source trees, and the first clone over a slow game
# link can take minutes, so it gets a longer ceiling of its own.
BACKUP_TIMEOUT = 15 * 60


# --- validation ------------------------------------------------------------

# A vulnbox service directory name. Deliberately strict: this name is spliced
# into remote paths and git refs, so anything outside this set (`..`, `/`, `;`,
# spaces, shell metacharacters) is rejected rather than quoted-and-hoped.
SERVICE_RE = re.compile(r"^[A-Za-z0-9._-]+$")

# SSH username charset (POSIX-portable account names). Never a leading '-'
# or '.': ssh would read `-x@host` as an option.
USERNAME_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]*$")

# DNS hostname charset; ip literals (v4 and v6) are checked separately. Same
# leading-character rule as usernames.
_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]*$")


def is_valid_service_name(name: str) -> bool:
    return bool(name) and name not in (".", "..") and SERVICE_RE.match(name) is not None


def resolve_host(raw) -> str:
    """The vulnbox address to ssh into — /config's `vm_ip` ("our team vm ip").

    Raises ValueError with a fix-it message when it is unset or malformed, so a
    typo fails before any connection is attempted.
    """
    host = str(raw or "").strip()
    if not host:
        raise ValueError("set our team's vulnbox address (vm_ip) in /config")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not _HOSTNAME_RE.match(host):
            raise ValueError(f"vm_ip is not a valid ip or hostname: {host!r}")
    return host


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def is_ipv6(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).version == 6
    except ValueError:
        return False


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


def parse_port_ranges(raw) -> PortRanges:
    """'9000-9999, 31337' → ((9000, 9999), (31337, 31337)).

    Used for `vulnbox_service_ports`: which published ports are game services
    (the ones other teams and the checker reach) as opposed to our own tooling.
    Empty → () → every published port counts.
    """
    ranges: list[tuple[int, int]] = []
    for part in str(raw or "").replace(" ", "").split(","):
        if not part:
            continue
        lo_s, sep, hi_s = part.partition("-")
        try:
            lo = int(lo_s)
            hi = int(hi_s) if sep else lo
        except ValueError:
            raise ValueError(f"invalid port or range: {part!r} (use e.g. 9000-9999,31337)")
        if not (1 <= lo <= hi <= 65535):
            raise ValueError(f"invalid port range: {part!r}")
        ranges.append((lo, hi))
    return tuple(ranges)


def in_port_ranges(port: int, ranges: PortRanges) -> bool:
    return not ranges or any(lo <= port <= hi for lo, hi in ranges)


def validate_service_ports(raw) -> str:
    """Write-time check for `vulnbox_service_ports`; returns the normalized form."""
    return ",".join(
        str(lo) if lo == hi else f"{lo}-{hi}" for lo, hi in parse_port_ranges(raw)
    )


# --- filesystem (lazy; never at import) ------------------------------------
#
# The api runs as root inside the container while ./vulnbox-data is a host
# bind mount owned by the host user. Everything created under it is handed to
# the data directory's owner (same rule as user_store._write_atomic) — or the
# key, the backups and job state turn up root-owned on the host, where the
# user can't read them and scripts/backup.sh can't copy them.

def own(path) -> None:
    """Give `path` to the data directory's owner. Best effort: a failure here
    (non-root api, odd filesystem) must never fail the operation itself."""
    try:
        st = data_dir().stat()
        os.chown(path, st.st_uid, st.st_gid, follow_symlinks=False)
    except OSError:
        pass


def ensure_dir(path: Path) -> None:
    """mkdir -p, handing every directory it creates to the data dir's owner."""
    path = Path(path)
    created = []
    p = path
    while not p.exists() and p != p.parent:
        created.append(p)
        p = p.parent
    path.mkdir(parents=True, exist_ok=True)
    for d in reversed(created):
        own(d)


def init_paths() -> None:
    """Create the data directory tree (called from create_app(), not import).
    Also re-owns keys/ and backups/ in case an earlier run left them root-owned."""
    for d in (keys_dir(), backups_dir()):
        ensure_dir(d)
        own(d)
