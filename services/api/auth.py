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
PUBLIC_PATHS = {"/", "/healthz", "/login", "/logout"}

# Role rank: higher number = more permissions. Decorator compares
# ROLE_RANK[user_role] >= ROLE_RANK[required_role].
ROLE_RANK: dict[str, int] = {"viewer": 0, "operator": 1, "admin": 2}
DEFAULT_ROLE_NEW_USER = "viewer"
# Backward compat: an existing users.yaml entry without a `role` field is
# treated as admin so the bootstrap user keeps full access.
LEGACY_ROLE = "admin"

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


def current_role() -> str:
    """Role of the currently authed user. 'viewer' if unauthed."""
    user = current_user()
    if not user:
        return "viewer"
    record = _load_users().get(user) or {}
    role = (record.get("role") or LEGACY_ROLE).strip()
    if role not in ROLE_RANK:
        role = "viewer"
    return role


def has_role(min_role: str) -> bool:
    return ROLE_RANK.get(current_role(), 0) >= ROLE_RANK.get(min_role, 99)


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


def requires_role(min_role: str):
    """Reject the request with 403 if the session user lacks `min_role`."""
    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if current_user() is None:
                return jsonify({"error": "unauthorized"}), 401
            if not has_role(min_role):
                return jsonify({
                    "error": "forbidden",
                    "required_role": min_role,
                    "your_role": current_role(),
                }), 403
            return fn(*args, **kwargs)
        return wrapper
    return deco
