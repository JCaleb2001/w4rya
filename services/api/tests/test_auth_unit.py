"""Unit coverage for `auth.py` — the module every request passes through.

The route suites exercise auth indirectly (a session either opens a door or it
doesn't). These tests go at the primitives: what `verify_password` does with a
half-written users.yaml, when the mtime cache decides to re-read, and how
`current_role` resolves a record that predates the role field.
"""

import os

import pytest
import yaml
from flask import session

import auth
import user_store


def write_users(
    path: str, users: dict, mtime: float | None = None, invalidate: bool = True
) -> None:
    """Write a users.yaml directly, optionally pinning its mtime.

    The cache tests need both knobs: a controlled timestamp (writing twice
    inside one filesystem timestamp tick is exactly what the mtime check
    cannot see) and the ability to leave the cache alone so the module's own
    staleness logic is what decides.
    """
    with open(path, "w") as f:
        yaml.safe_dump({"users": users}, f)
    if mtime is not None:
        os.utime(path, (mtime, mtime))
    if invalidate:
        auth.invalidate_users_cache()


# --- verify_password -------------------------------------------------------

def test_verify_password_rejects_an_unknown_user(users_file):
    write_users(users_file, {"alice": {"password_hash": user_store.hash_password("secret-pw")}})
    assert auth.verify_password("mallory", "secret-pw") is False


def test_verify_password_rejects_a_record_with_an_empty_hash(users_file):
    """A hand-edited users.yaml with `password_hash: ""` must not become an
    account that accepts every password."""
    write_users(users_file, {"alice": {"password_hash": ""}})
    assert auth.verify_password("alice", "") is False
    assert auth.verify_password("alice", "anything") is False


def test_verify_password_rejects_a_record_with_no_hash_field(users_file):
    write_users(users_file, {"alice": {"role": "admin"}})
    assert auth.verify_password("alice", "anything") is False


def test_verify_password_swallows_a_malformed_bcrypt_hash(users_file):
    """bcrypt.checkpw raises ValueError on a hash that isn't one; the caller
    is a login handler, so this has to come back as a plain False."""
    write_users(users_file, {"alice": {"password_hash": "not-a-bcrypt-hash"}})
    assert auth.verify_password("alice", "anything") is False


def test_verify_password_accepts_the_right_password_and_only_that_one(users_file):
    user_store.create_user("alice", "correct-horse", "viewer", overwrite=True)
    auth.invalidate_users_cache()
    assert auth.verify_password("alice", "correct-horse") is True
    assert auth.verify_password("alice", "correct-horsE") is False
    assert auth.verify_password("alice", "") is False


def test_verify_password_on_a_missing_file_is_false(users_file):
    assert not os.path.exists(users_file)
    assert auth.verify_password("alice", "anything") is False


# --- _load_users mtime cache ----------------------------------------------

def test_load_users_sees_a_rewrite_with_a_newer_mtime(users_file):
    """The documented reason `docker compose restart api` is optional after
    editing users.yaml."""
    write_users(users_file, {"alice": {"role": "viewer"}}, mtime=1_000_000.0)
    assert auth._load_users() == {"alice": {"role": "viewer"}}

    write_users(users_file, {"bob": {"role": "admin"}}, mtime=1_000_010.0, invalidate=False)
    assert auth._load_users() == {"bob": {"role": "admin"}}


def test_load_users_serves_the_cache_while_the_mtime_is_unchanged(users_file):
    """The flip side of the optimisation: a write that lands inside the same
    timestamp is invisible until something invalidates."""
    write_users(users_file, {"alice": {"role": "viewer"}}, mtime=1_000_000.0)
    assert auth._load_users() == {"alice": {"role": "viewer"}}

    write_users(users_file, {"bob": {"role": "admin"}}, mtime=1_000_000.0, invalidate=False)
    assert auth._load_users() == {"alice": {"role": "viewer"}}

    auth.invalidate_users_cache()
    assert auth._load_users() == {"bob": {"role": "admin"}}


def test_invalidate_clears_both_cache_slots(users_file):
    write_users(users_file, {"alice": {"role": "viewer"}})
    auth._load_users()
    assert auth._users_cache is not None
    auth.invalidate_users_cache()
    assert auth._users_cache is None
    assert auth._users_mtime is None


def test_load_users_tolerates_a_corrupt_file(users_file):
    with open(users_file, "w") as f:
        f.write("users: [unclosed\n")
    auth.invalidate_users_cache()
    assert auth._load_users() == {}
    assert auth.user_count() == 0


def test_user_count_reflects_the_file(users_file):
    write_users(users_file, {"alice": {}, "bob": {}})
    assert auth.user_count() == 2


# --- current_role ----------------------------------------------------------

def test_current_role_is_viewer_when_unauthenticated(app):
    with app.test_request_context("/query"):
        assert auth.current_user() is None
        assert auth.current_role() == "viewer"


@pytest.mark.parametrize("role", ["viewer", "operator", "admin"])
def test_current_role_resolves_the_stored_role(app, users_file, role):
    write_users(users_file, {"alice": {"role": role}})
    with app.test_request_context("/query"):
        session["user"] = "alice"
        assert auth.current_role() == role


def test_current_role_treats_a_roleless_record_as_admin(app, users_file):
    """LEGACY_ROLE back-compat: users.yaml entries written before roles
    existed have no `role:` key, and the bootstrap admin is one of them.
    Defaulting them to viewer would lock the original operator out of
    /config and /audit on upgrade."""
    write_users(users_file, {"alice": {"password_hash": "x"}})
    with app.test_request_context("/query"):
        session["user"] = "alice"
        assert auth.current_role() == "admin"


def test_current_role_clamps_an_unrecognised_role_down_to_viewer(app, users_file):
    """A typo'd role in users.yaml must fail closed, not open."""
    write_users(users_file, {"alice": {"role": "superuser"}})
    with app.test_request_context("/query"):
        session["user"] = "alice"
        assert auth.current_role() == "viewer"


def test_current_role_ignores_surrounding_whitespace(app, users_file):
    write_users(users_file, {"alice": {"role": "  operator  "}})
    with app.test_request_context("/query"):
        session["user"] = "alice"
        assert auth.current_role() == "operator"


def test_a_session_for_a_deleted_user_gets_no_role_at_all(app, users_file):
    """Regression for a privilege escalation.

    `current_role` used to do `_load_users().get(user) or {}` and then fall back
    to LEGACY_ROLE, which made a user *absent* from users.yaml indistinguishable
    from a legacy roleless record — so they came back as admin. Sessions are
    stateless signed cookies, so a deleted teammate kept a working one, and it
    now outranked whatever they had before they were removed.
    """
    write_users(users_file, {"alice": {"role": "viewer"}})
    with app.test_request_context("/query"):
        session["user"] = "deleted_teammate"
        assert auth.current_role() == "viewer"
        assert auth.has_role("admin") is False
        assert auth.has_role("operator") is False


# --- has_role --------------------------------------------------------------

RANKS = ["viewer", "operator", "admin"]


@pytest.mark.parametrize("required", RANKS)
@pytest.mark.parametrize("actual", RANKS)
def test_has_role_covers_the_whole_rank_matrix(app, users_file, actual, required):
    write_users(users_file, {"alice": {"role": actual}})
    expected = auth.ROLE_RANK[actual] >= auth.ROLE_RANK[required]
    with app.test_request_context("/query"):
        session["user"] = "alice"
        assert auth.has_role(required) is expected


def test_has_role_fails_closed_for_an_unknown_requirement(app, users_file):
    """A decorator written as requires_role('superadmin') must reject
    everyone rather than waving admin through."""
    write_users(users_file, {"alice": {"role": "admin"}})
    with app.test_request_context("/query"):
        session["user"] = "alice"
        assert auth.has_role("superadmin") is False


def test_has_role_on_an_anonymous_request_only_grants_viewer(app):
    with app.test_request_context("/query"):
        assert auth.has_role("viewer") is True
        assert auth.has_role("operator") is False
        assert auth.has_role("admin") is False


# --- require_auth ----------------------------------------------------------

def test_require_auth_lets_options_through(app):
    """CORS preflight carries no cookie; 401ing it would break every
    cross-origin write from the frontend before the real request is sent."""
    with app.test_request_context("/query", method="OPTIONS"):
        assert auth.require_auth() is None


@pytest.mark.parametrize("path", sorted(auth.PUBLIC_PATHS))
def test_require_auth_lets_public_paths_through(app, path):
    with app.test_request_context(path):
        assert auth.require_auth() is None


def test_require_auth_blocks_an_anonymous_request(app):
    with app.test_request_context("/query"):
        body, status = auth.require_auth()
        assert status == 401
        assert body.get_json() == {"error": "unauthorized"}


def test_require_auth_passes_a_session_holder(app, users_file):
    write_users(users_file, {"alice": {"role": "viewer"}})
    with app.test_request_context("/query"):
        session["user"] = "alice"
        assert auth.require_auth() is None


# --- regression: a deleted teammate's cookie must stop working --------------

def test_a_deleted_users_session_is_rejected(app, users_file):
    """Sessions are stateless signed cookies, so deleting an account does not
    invalidate the cookies already issued for it. Before this was fixed, a
    removed teammate kept access for the 7-day cookie lifetime — and
    current_role() resolved them to *admin*, because a missing record was
    indistinguishable from a legacy roleless one."""
    import user_store

    user_store.create_user("gone", "temp-password-1", "viewer", overwrite=True)
    auth.invalidate_users_cache()

    client = app.test_client()
    with client.session_transaction() as sess:
        sess["user"] = "gone"
    assert client.get("/me").status_code == 200

    user_store.delete_user("gone")
    auth.invalidate_users_cache()

    assert client.get("/me").status_code == 401
    assert client.get("/users").status_code == 401


def test_a_session_for_an_unknown_user_never_resolves_to_admin(app, users_file):
    """The escalation half of the same bug, checked directly."""
    with app.test_request_context():
        from flask import session as flask_session
        flask_session["user"] = "never-existed"
        assert auth.current_role() == "viewer"
        assert auth.has_role("admin") is False
        assert auth.has_role("operator") is False


def test_a_roleless_record_is_still_treated_as_admin(app, users_file):
    """The legacy fallback itself must survive the fix: a pre-roles bootstrap
    entry with no `role` key keeps full access."""
    import yaml

    with open(users_file, "w") as f:
        yaml.safe_dump({"users": {"old": {"password_hash": "$2b$04$notarealhash"}}}, f)
    auth.invalidate_users_cache()

    with app.test_request_context():
        from flask import session as flask_session
        flask_session["user"] = "old"
        assert auth.current_role() == "admin"
