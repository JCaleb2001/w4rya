"""The SSH keypair we submit to the A/D platform for vulnbox access.

Generated with `ssh-keygen` (ed25519). The private key is written 0600 and is
only ever served as a file download — never returned in a JSON body or
rendered on screen (ECSC §6.12 screen recording). The public key is safe to
show and copy.

Files are chowned to the data directory's owner, same reason as
`user_store._write_atomic`: the api runs as root inside the container over a
host bind mount, so without it they turn up root-owned on the host.
"""

from __future__ import annotations

import os
import socket
import subprocess
from datetime import datetime, timezone
from typing import Optional

from . import config


def _chown_to_parent(path) -> None:
    try:
        st = os.stat(path.parent)
        os.chown(path, st.st_uid, st.st_gid)
    except OSError:
        pass


def _fingerprint(pub_path) -> Optional[str]:
    """SHA256 fingerprint via `ssh-keygen -lf`. Returns the 'SHA256:...' token."""
    try:
        out = subprocess.run(
            ["ssh-keygen", "-lf", str(pub_path)],
            capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    for tok in out.stdout.split():
        if tok.startswith("SHA256:"):
            return tok
    return None


def status() -> dict:
    """Current key state. Never includes any private material."""
    priv = config.private_key_path()
    pub = config.public_key_path()
    if not (priv.exists() and pub.exists()):
        return {"exists": False}
    try:
        created = datetime.fromtimestamp(
            os.stat(priv).st_mtime, tz=timezone.utc
        ).isoformat()
    except OSError:
        created = None
    return {
        "exists": True,
        "public_key": pub.read_text().strip(),
        "fingerprint": _fingerprint(pub),
        "created_at": created,
    }


def generate(rotate: bool = False) -> dict:
    """Create a fresh ed25519 keypair. Refuses to clobber an existing key
    unless `rotate=True` (rotating invalidates the key already on the box)."""
    config.ensure_dir(config.keys_dir())
    priv = config.private_key_path()
    pub = config.public_key_path()
    if priv.exists() and not rotate:
        raise ValueError("a key already exists; pass rotate=true to replace it")
    # ssh-keygen refuses to write over an existing file, so clear first.
    for p in (priv, pub):
        try:
            p.unlink()
        except FileNotFoundError:
            pass
    comment = f"w4rya-vulnbox@{socket.gethostname()}"
    try:
        result = subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-N", "", "-C", comment, "-f", str(priv)],
            capture_output=True, text=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as e:
        raise RuntimeError(f"ssh-keygen failed to run: {e}")
    if result.returncode != 0:
        raise RuntimeError(f"ssh-keygen failed: {result.stderr.strip()}")
    os.chmod(priv, 0o600)
    try:
        os.chmod(pub, 0o644)
    except OSError:
        pass
    _chown_to_parent(priv)
    _chown_to_parent(pub)
    return status()


def private_key_path():
    """Path to the private key for the download route. Caller checks exists()."""
    return config.private_key_path()


def forget_host_key() -> bool:
    """Drop the pinned vulnbox host key (used after the box is re-provisioned
    and its host key legitimately changes). True if one was removed."""
    kh = config.known_hosts_path()
    try:
        kh.unlink()
        return True
    except FileNotFoundError:
        return False
