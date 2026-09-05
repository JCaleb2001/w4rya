"""Import-time contracts.

These are cheap and they pin the two things that cost the most when they break:
the api refusing to start, and a route rename that silently breaks the frontend.
"""

import subprocess
import sys

import pytest


def test_app_imports_with_only_the_two_required_env_vars(app):
    """A dead-but-syntactically-valid TIMESCALE url is enough, because
    database.Pool opens lazily. This is what keeps the suite offline."""
    assert app.name == "webservice"


def test_missing_secret_key_refuses_to_start(tmp_path):
    """The #1 install failure: .env.example ships W4RYA_SECRET_KEY empty, and
    an api that boots without a signing key would silently issue forgeable
    session cookies. Run in a subprocess for a clean import."""
    code = (
        "import os, sys;"
        "os.environ.pop('W4RYA_SECRET_KEY', None);"
        "os.environ['TIMESCALE']='postgres://w4rya@127.0.0.1:1/w4rya';"
        "sys.path.insert(0, '.');"
        "import webservice"
    )
    proc = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True, text=True, cwd="/app",
        env={"PATH": "/usr/local/bin:/usr/bin:/bin", "TIMESCALE": "postgres://x@127.0.0.1:1/y"},
    )
    assert proc.returncode != 0
    assert "W4RYA_SECRET_KEY" in proc.stderr
    assert "RuntimeError" in proc.stderr


def test_session_cookie_is_hardened(app):
    cfg = app.config
    assert cfg["SESSION_COOKIE_NAME"] == "w4rya_session"
    assert cfg["SESSION_COOKIE_HTTPONLY"] is True
    assert cfg["SESSION_COOKIE_SAMESITE"] == "Lax"
    # Secure follows W4RYA_COOKIE_SECURE, which is off for plain-HTTP LAN use.
    assert isinstance(cfg["SESSION_COOKIE_SECURE"], bool)


# Routes the frontend calls by literal string in frontend/src/api.ts. CLAUDE.md
# calls these a contract: adding fields is safe, renaming or removing is not.
FRONTEND_CONTRACT = [
    "/me", "/login", "/logout", "/setup", "/setup/status",
    "/users", "/users/<username>", "/users/<username>/role", "/users/<username>/password",
    "/query", "/tags", "/services", "/services/stats", "/flag_regex", "/tick_info",
    "/star", "/stats", "/under_attack", "/attacks",
    "/config", "/config/services", "/config/teams",
    "/rules", "/rules/<int:sid>", "/rules/block-ip", "/rules/reload",
    "/audit", "/audit/actors", "/audit/export.csv",
    "/attack/replay", "/healthz",
]


@pytest.mark.parametrize("path", FRONTEND_CONTRACT)
def test_route_the_frontend_depends_on_still_exists(app, path):
    existing = {r.rule for r in app.url_map.iter_rules()}
    assert path in existing, (
        f"{path} is gone — frontend/src/api.ts calls it and will 404 at runtime"
    )
