"""Authentication for the w4rya API.

Users live in a YAML file (mounted at /app/auth/users.yaml inside the api
container). Sessions are stored in a signed httpOnly cookie via Flask.

No AI / LLM is involved at runtime — credential check is plain bcrypt.
"""

import os
from functools import wraps
from typing import Optional

import bcrypt
import yaml
from flask import jsonify, request, session

USERS_FILE = os.environ.get("W4RYA_USERS_FILE", "/app/auth/users.yaml")

# Paths that bypass the auth guard. Everything else requires a session.
# `/me` is intentionally NOT public — the frontend uses its 401 response as
# the "not logged in" signal.
PUBLIC_PATHS = {"/", "/login", "/logout"}

_users_cache: Optional[dict] = None
_users_mtime: Optional[float] = None


def _load_users() -> dict:
    """Read users from disk, with mtime-based caching."""
    global _users_cache, _users_mtime
    try:
        mtime = os.path.getmtime(USERS_FILE)
    except OSError:
        return {}
    if _users_cache is not None and _users_mtime == mtime:
        return _users_cache
    try:
        with open(USERS_FILE) as f:
            data = yaml.safe_load(f) or {}
    except (OSError, yaml.YAMLError):
        return {}
    users = data.get("users") or {}
    _users_cache = users
    _users_mtime = mtime
    return users


def verify_password(username: str, password: str) -> bool:
    users = _load_users()
    record = users.get(username)
    if not record:
        return False
    hashed = (record.get("password_hash") or "").encode()
    if not hashed:
        return False
    try:
        return bcrypt.checkpw(password.encode(), hashed)
    except (ValueError, TypeError):
        return False


def current_user() -> Optional[str]:
    return session.get("user")


def require_auth():
    """Flask before_request hook. Return a 401 response if blocked, else None."""
    if request.method == "OPTIONS":
        return None
    if request.path in PUBLIC_PATHS:
        return None
    if current_user() is None:
        return jsonify({"error": "unauthorized"}), 401
    return None


def login_required(fn):
    """Decorator alternative to the before_request hook."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if current_user() is None:
            return jsonify({"error": "unauthorized"}), 401
        return fn(*args, **kwargs)
    return wrapper
