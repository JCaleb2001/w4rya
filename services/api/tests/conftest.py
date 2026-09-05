"""Test bootstrap for the w4rya api.

Two jobs:

1. Make `services/api/` importable from this subdir without a setup.py.
2. Set the environment BEFORE anything imports `webservice`.

On (2): `webservice.py` runs `db = database.Pool(os.environ["TIMESCALE"])` at
import time, and raises RuntimeError when `W4RYA_SECRET_KEY` is unset. That
looks like it forces a live database on the test suite, but `database.Pool`
passes `open=False` to psycopg_pool, which neither connects nor validates the
conninfo. So a syntactically-valid-but-dead URL is enough to import the module,
and the whole route suite runs offline in a couple of seconds.

The one rule that follows: tests use `webservice.application` directly and must
never call `webservice.create_app()` — that is what opens the pool and runs the
three init_schema() calls.
"""

import os
import sys
import tempfile

# --- (1) import path -------------------------------------------------------
_HERE = os.path.dirname(os.path.abspath(__file__))
_API = os.path.abspath(os.path.join(_HERE, ".."))
if _API not in sys.path:
    sys.path.insert(0, _API)

# --- (2) environment, before any project import ----------------------------
_TMP = tempfile.mkdtemp(prefix="w4rya-tests-")
os.environ.setdefault("W4RYA_SECRET_KEY", "test-secret-not-a-real-key")
os.environ.setdefault("TIMESCALE", "postgres://w4rya@127.0.0.1:1/w4rya")
os.environ.setdefault("W4RYA_USERS_FILE", os.path.join(_TMP, "users.yaml"))
os.environ.setdefault("W4RYA_RULES_FILE", os.path.join(_TMP, "suricata.rules"))

import pytest  # noqa: E402

import auth  # noqa: E402
import rate_limit  # noqa: E402
import user_store  # noqa: E402


@pytest.fixture(scope="session")
def app():
    import webservice
    webservice.application.config["TESTING"] = True
    return webservice.application


@pytest.fixture
def webservice_mod(app):
    import webservice
    return webservice


@pytest.fixture(autouse=True)
def users_file(tmp_path, monkeypatch):
    """Redirect the user store at a per-test file.

    Both modules must be patched: `auth.py` does `from user_store import
    USERS_FILE`, which binds the value at import time, so patching only
    `user_store.USERS_FILE` would leave auth reading the real users.yaml.
    """
    path = str(tmp_path / "users.yaml")
    monkeypatch.setattr(user_store, "USERS_FILE", path)
    monkeypatch.setattr(auth, "USERS_FILE", path)
    monkeypatch.setattr(user_store, "BCRYPT_ROUNDS", 4)
    auth.invalidate_users_cache()
    yield path
    auth.invalidate_users_cache()


@pytest.fixture(autouse=True)
def _reset_rate_limit():
    """rate_limit keeps module-global buckets; without this they leak between
    tests and a later test inherits an earlier one's lockout."""
    rate_limit._failures.clear()
    yield
    rate_limit._failures.clear()


class FakeCursor:
    """Stands in for whatever database.Pool hands back. Every query method
    returns an empty result, which is what the route layer has to cope with on
    a fresh install anyway."""

    def __init__(self, rows=None):
        self._rows = rows if rows is not None else []

    def execute(self, *a, **kw):
        return self

    def fetchall(self):
        return list(self._rows)

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def __iter__(self):
        return iter(self._rows)

    def __getattr__(self, name):
        # database.Pool exposes query helpers (flow_query, tag_list, …) straight
        # off the connection object. Return an empty list for any of them rather
        # than enumerating a moving target.
        def _any(*a, **kw):
            return []
        return _any


class FakeConnection:
    def __init__(self, rows=None):
        self._cur = FakeCursor(rows)

    def __enter__(self):
        return self._cur

    def __exit__(self, *a):
        return False


class FakeDb:
    def __init__(self, rows=None):
        self.rows = rows

    def connection(self):
        return FakeConnection(self.rows)


@pytest.fixture
def fake_db(monkeypatch, webservice_mod):
    db = FakeDb()
    monkeypatch.setattr(webservice_mod, "db", db)
    return db


def _client_as(app, users_path, username, role):
    """A test client already carrying a session for `username`.

    The session is set directly rather than by POSTing /login: it keeps the
    suite off bcrypt on every request, and role tests care about the guard, not
    about password checking (test_auth_unit covers that).
    """
    user_store.create_user(username, "test-password-123", role, overwrite=True)
    auth.invalidate_users_cache()
    client = app.test_client()
    with client.session_transaction() as sess:
        sess["user"] = username
    return client


@pytest.fixture
def anon(app):
    return app.test_client()


@pytest.fixture
def viewer(app, users_file):
    return _client_as(app, users_file, "viewer_user", "viewer")


@pytest.fixture
def operator(app, users_file):
    return _client_as(app, users_file, "operator_user", "operator")


@pytest.fixture
def admin(app, users_file):
    return _client_as(app, users_file, "admin_user", "admin")
