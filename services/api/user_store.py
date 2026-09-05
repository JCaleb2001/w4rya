"""Shared user store for w4rya — the single writer for auth/users.yaml.

Read paths stay in `auth.py` (mtime-cached, hot on every request). This module
owns every *mutation*, and is imported by both the HTTP endpoints
(`/setup`, `/users`) and the `auth/add_user.py` CLI so the validation and
hashing rules can't drift apart.

Cross-process safety: the api runs 3 gunicorn workers, each with its own
users cache. Every mutation takes an exclusive flock on a sidecar lock file
and re-reads users.yaml *inside* the lock, so a "create the first admin"
race between two workers can't produce two first admins.

No AI / LLM at runtime — credential handling is plain bcrypt.
"""

from __future__ import annotations

import fcntl
import os
import re
import tempfile
from contextlib import contextmanager
from typing import Optional

import bcrypt
import yaml

# Single source of truth for the path; auth.py imports this.
USERS_FILE = os.environ.get("W4RYA_USERS_FILE", "/app/auth/users.yaml")

USERNAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
VALID_ROLES = ("viewer", "operator", "admin")
MIN_PASSWORD_LEN = 8
BCRYPT_ROUNDS = 12


class UserStoreError(Exception):
    """Validation / conflict error. `code` is the HTTP status to answer with."""

    def __init__(self, message: str, code: int = 400):
        super().__init__(message)
        self.message = message
        self.code = code


def validate_username(username: str) -> str:
    username = (username or "").strip()
    if not USERNAME_RE.match(username):
        raise UserStoreError(
            "username must match [A-Za-z0-9_-]{1,32}", 400
        )
    return username


def validate_password(password: str) -> str:
    if not password:
        raise UserStoreError("password required", 400)
    if len(password) < MIN_PASSWORD_LEN:
        raise UserStoreError(
            f"password must be at least {MIN_PASSWORD_LEN} characters", 400
        )
    return password


def validate_role(role: str) -> str:
    role = (role or "").strip()
    if role not in VALID_ROLES:
        raise UserStoreError(
            f"role must be one of: {', '.join(VALID_ROLES)}", 400
        )
    return role


def hash_password(password: str) -> str:
    return bcrypt.hashpw(
        password.encode(), bcrypt.gensalt(BCRYPT_ROUNDS)
    ).decode()


@contextmanager
def _locked():
    """Exclusive advisory lock shared by every process touching users.yaml."""
    parent = os.path.dirname(USERS_FILE) or "."
    os.makedirs(parent, exist_ok=True)
    lock_path = USERS_FILE + ".lock"
    existed = os.path.exists(lock_path)
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    if not existed:
        # Same reason as _write_atomic: the api runs as root inside the
        # container over a host bind mount, so without this the lock file turns
        # up root-owned on the host and the user cannot clear it themselves.
        try:
            st = os.stat(parent)
            os.chown(lock_path, st.st_uid, st.st_gid)
        except OSError:
            pass
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _read_raw() -> dict:
    """Whole-document read. Unlike auth._load_users this is never cached —
    callers use it inside the lock, where staleness would be a bug."""
    try:
        with open(USERS_FILE) as f:
            data = yaml.safe_load(f) or {}
    except FileNotFoundError:
        return {}
    except (OSError, yaml.YAMLError) as e:
        # Refuse to write over a file we can't parse — that would silently
        # destroy existing accounts.
        raise UserStoreError(f"users file is unreadable: {e}", 500)
    if not isinstance(data, dict):
        raise UserStoreError("users file is malformed (expected a mapping)", 500)
    return data


def _write_atomic(data: dict) -> None:
    parent = os.path.dirname(USERS_FILE) or "."
    fd, tmp = tempfile.mkstemp(dir=parent, prefix=".users.", suffix=".yaml")
    try:
        with os.fdopen(fd, "w") as f:
            yaml.safe_dump(data, f, default_flow_style=False, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        # The api container runs as root while the bind mount is owned by the
        # host user. Inherit the directory's owner so users.yaml stays
        # editable from the host instead of turning up root-owned.
        try:
            st = os.stat(parent)
            os.chown(tmp, st.st_uid, st.st_gid)
        except OSError:
            pass
        os.replace(tmp, USERS_FILE)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _users_of(data: dict) -> dict:
    users = data.get("users")
    return users if isinstance(users, dict) else {}


def count() -> int:
    """Number of accounts on disk. Uncached — this gates first-run setup."""
    return len(_users_of(_read_raw()))


def users_exist() -> bool:
    return count() > 0


def list_users() -> list[dict]:
    """Accounts without their hashes, sorted by name."""
    users = _users_of(_read_raw())
    out = []
    for name, rec in sorted(users.items()):
        rec = rec if isinstance(rec, dict) else {}
        # Mirror auth.current_role(): a missing role means a pre-roles entry,
        # which is treated as admin.
        role = (rec.get("role") or "admin").strip()
        out.append({"username": name, "role": role if role in VALID_ROLES else "viewer"})
    return out


def create_user(
    username: str,
    password: str,
    role: str,
    *,
    only_if_empty: bool = False,
    overwrite: bool = False,
) -> dict:
    """Create (or overwrite) an account.

    only_if_empty — refuse unless the store is empty. This is what makes the
    public /setup endpoint self-closing: the check happens inside the lock,
    at write time, so concurrent first-run POSTs can't both win.
    """
    username = validate_username(username)
    validate_password(password)
    role = validate_role(role)
    hashed = hash_password(password)

    with _locked():
        data = _read_raw()
        users = dict(_users_of(data))
        if only_if_empty and users:
            raise UserStoreError("setup already completed", 409)
        if username in users and not overwrite:
            raise UserStoreError(f"user '{username}' already exists", 409)
        users[username] = {"password_hash": hashed, "role": role}
        data["users"] = users
        _write_atomic(data)
    return {"username": username, "role": role}


def set_password(username: str, password: str) -> dict:
    username = validate_username(username)
    validate_password(password)
    hashed = hash_password(password)
    with _locked():
        data = _read_raw()
        users = dict(_users_of(data))
        if username not in users:
            raise UserStoreError(f"no such user '{username}'", 404)
        rec = dict(users[username]) if isinstance(users[username], dict) else {}
        rec["password_hash"] = hashed
        rec.setdefault("role", "admin")
        users[username] = rec
        data["users"] = users
        _write_atomic(data)
    return {"username": username, "role": users[username].get("role")}


def set_role(username: str, role: str) -> dict:
    username = validate_username(username)
    role = validate_role(role)
    with _locked():
        data = _read_raw()
        users = dict(_users_of(data))
        if username not in users:
            raise UserStoreError(f"no such user '{username}'", 404)
        if role != "admin" and _would_orphan_admins(users, dropping=username):
            raise UserStoreError("refusing to demote the last admin", 409)
        rec = dict(users[username]) if isinstance(users[username], dict) else {}
        rec["role"] = role
        users[username] = rec
        data["users"] = users
        _write_atomic(data)
    return {"username": username, "role": role}


def delete_user(username: str) -> None:
    username = validate_username(username)
    with _locked():
        data = _read_raw()
        users = dict(_users_of(data))
        if username not in users:
            raise UserStoreError(f"no such user '{username}'", 404)
        if _would_orphan_admins(users, dropping=username):
            raise UserStoreError("refusing to delete the last admin", 409)
        del users[username]
        data["users"] = users
        _write_atomic(data)


def _would_orphan_admins(users: dict, *, dropping: str) -> bool:
    """True if removing/demoting `dropping` leaves the install with no admin
    — which would lock everyone out of /config and /audit for good."""
    admins = set()
    for name, rec in users.items():
        rec = rec if isinstance(rec, dict) else {}
        # No role field == legacy admin, same rule as auth.current_role().
        if (rec.get("role") or "admin").strip() == "admin":
            admins.add(name)
    return admins == {dropping}
