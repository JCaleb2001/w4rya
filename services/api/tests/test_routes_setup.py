"""The first-run lifecycle over HTTP, with no database involved.

Covers the behaviour that made a fresh clone unusable: a login form that could
never succeed, and a rate limiter that locked you out of the account you were
about to create.
"""

import rate_limit
import user_store


def recorded_failures() -> int:
    """Total failures actually recorded.

    Not `assert not rate_limit._failures`: the bucket is a defaultdict, so
    merely *checking* a key materialises an empty deque for it. What matters is
    that nothing was appended.
    """
    return sum(len(q) for q in rate_limit._failures.values())


def test_status_reports_needs_setup_when_empty(anon):
    resp = anon.get("/setup/status")
    assert resp.status_code == 200
    assert resp.get_json() == {"needs_setup": True}


def test_login_on_a_fresh_install_says_so_instead_of_invalid_credentials(anon):
    """The old behaviour was 401 'invalid credentials', which sent people
    hunting for a password that never existed."""
    resp = anon.post("/login", json={"username": "caleb", "password": "whatever1"})
    assert resp.status_code == 409
    body = resp.get_json()
    assert body["needs_setup"] is True
    assert "no accounts" in body["error"]


def test_fresh_install_login_never_burns_the_rate_limiter(anon):
    """Regression fence. If this starts recording failures, an installer who
    pokes the login form locks out the username they are about to create."""
    for _ in range(10):
        assert anon.post("/login", json={"username": "caleb", "password": "x" * 10}).status_code == 409
    assert recorded_failures() == 0, "a fresh-install login consumed a rate-limit slot"


def test_setup_rejects_a_short_password_without_penalty(anon):
    resp = anon.post("/setup", json={"username": "caleb", "password": "short"})
    assert resp.status_code == 400
    assert "8 characters" in resp.get_json()["error"]
    # A typo is not abuse — it must not count against the bucket.
    assert recorded_failures() == 0


def test_setup_rejects_a_bad_username(anon):
    resp = anon.post("/setup", json={"username": "has space", "password": "longenough"})
    assert resp.status_code == 400
    assert "username" in resp.get_json()["error"]


def test_setup_creates_an_admin_and_opens_the_session(anon):
    resp = anon.post("/setup", json={"username": "caleb", "password": "longenough1"})
    assert resp.status_code == 201
    body = resp.get_json()
    assert body == {"user": "caleb", "role": "admin"}

    # The role must be written explicitly: 'viewer' would leave the first user
    # unable to reach /config or /audit, i.e. a still-unusable install.
    assert user_store.list_users() == [{"username": "caleb", "role": "admin"}]

    # Session is live on the same client — no separate login step.
    me = anon.get("/me")
    assert me.status_code == 200
    assert me.get_json() == {"user": "caleb", "role": "admin"}


def test_status_flips_after_setup(anon):
    anon.post("/setup", json={"username": "caleb", "password": "longenough1"})
    assert anon.get("/setup/status").get_json() == {"needs_setup": False}


def test_setup_closes_itself_permanently(anon, app):
    anon.post("/setup", json={"username": "caleb", "password": "longenough1"})
    other = app.test_client()
    resp = other.post("/setup", json={"username": "mallory", "password": "longenough1"})
    assert resp.status_code == 409
    assert resp.get_json()["error"] == "setup already completed"
    assert [u["username"] for u in user_store.list_users()] == ["caleb"]


def test_repeated_attempts_after_setup_get_rate_limited(anon, app):
    anon.post("/setup", json={"username": "caleb", "password": "longenough1"})
    other = app.test_client()
    codes = [
        other.post("/setup", json={"username": f"m{i}", "password": "longenough1"}).status_code
        for i in range(4)
    ]
    assert codes[:3] == [409, 409, 409]
    assert codes[3] == 429
    assert other.post(
        "/setup", json={"username": "m9", "password": "longenough1"}
    ).get_json()["retry_after_sec"] >= 0


def test_login_works_with_the_account_setup_created(anon, app):
    anon.post("/setup", json={"username": "caleb", "password": "longenough1"})
    fresh = app.test_client()
    resp = fresh.post("/login", json={"username": "caleb", "password": "longenough1"})
    assert resp.status_code == 200
    assert resp.get_json() == {"user": "caleb", "role": "admin"}
    assert fresh.post("/login", json={"username": "caleb", "password": "wrong"}).status_code == 401
