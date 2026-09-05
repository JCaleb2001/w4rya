"""Every route is behind the session guard unless it is explicitly public.

This is driven off `application.url_map` rather than a hand-written list, so a
route added later without an auth thought fails the suite on its own. That
self-extending property is the whole point of the file.
"""

import re

import pytest

import auth

# Concrete values to substitute for URL converters. The value only has to route;
# the guard fires before the view runs, so it is never dereferenced.
_UUID = "00000000-0000-0000-0000-000000000000"


def _concrete_path(rule) -> str:
    """Turn '/flow/<flow_id>/notes' into a path we can actually request."""
    def sub(m):
        spec = m.group(1)
        if spec.startswith("int:"):
            return "1"
        if spec.startswith("path:"):
            return "x"
        return _UUID
    return re.sub(r"<([^>]+)>", sub, rule.rule)


def _testable_rules(app):
    for rule in app.url_map.iter_rules():
        if rule.endpoint == "static":
            continue
        methods = sorted(rule.methods - {"HEAD", "OPTIONS"})
        if not methods:
            continue
        yield rule, methods[0]


def _ids(app):
    return [f"{m} {r.rule}" for r, m in _testable_rules(app)]


@pytest.fixture
def routes(app):
    return list(_testable_rules(app))


def test_url_map_is_not_empty(app):
    # Guards against the parametrisation below silently covering nothing.
    assert len(list(_testable_rules(app))) > 20


def test_every_nonpublic_route_401s_without_a_session(anon, app):
    """The core contract. No mocking needed: before_request returns before the
    view is reached, so the database is never touched."""
    checked = 0
    for rule, method in _testable_rules(app):
        path = _concrete_path(rule)
        if path in auth.PUBLIC_PATHS:
            continue
        resp = anon.open(path, method=method)
        assert resp.status_code == 401, (
            f"{method} {rule.rule} returned {resp.status_code}, expected 401 "
            f"(is it missing from PUBLIC_PATHS, or newly public by accident?)"
        )
        assert resp.is_json, f"{method} {rule.rule} 401'd with non-JSON body"
        assert resp.get_json() == {"error": "unauthorized"}
        checked += 1
    assert checked > 20


@pytest.mark.parametrize("path", sorted(auth.PUBLIC_PATHS))
def test_public_paths_are_reachable_anonymously(anon, path):
    """A public path must not answer 401. What it *does* answer varies (200,
    400, 405, 409), and that is fine — this pins only that the guard let it
    through."""
    for method in ("GET", "POST"):
        resp = anon.open(path, method=method)
        if resp.status_code == 405:
            continue
        assert resp.status_code != 401, f"{method} {path} is in PUBLIC_PATHS but 401'd"


def test_public_paths_are_exactly_what_we_expect():
    """A regression fence: widening the anonymous surface should be a
    deliberate edit to this list, not a side effect."""
    assert auth.PUBLIC_PATHS == {
        "/", "/healthz", "/login", "/logout", "/setup", "/setup/status",
    }


def test_options_bypasses_the_guard(anon):
    """CORS preflight is allowed through by design (auth.require_auth)."""
    resp = anon.open("/query", method="OPTIONS")
    assert resp.status_code != 401


def test_me_is_not_public(anon):
    """The frontend uses /me's 401 as its 'not logged in' signal, so it must
    never become public."""
    assert "/me" not in auth.PUBLIC_PATHS
    assert anon.get("/me").status_code == 401


def test_authenticated_user_passes_the_guard(viewer, fake_db):
    resp = viewer.get("/me")
    assert resp.status_code == 200
    assert resp.get_json()["user"] == "viewer_user"


def test_unknown_path_does_not_leak_that_it_is_unknown(anon):
    """An anonymous request for a route that does not exist should still be a
    401, not a 404 — otherwise the 404s map the private surface."""
    resp = anon.get("/definitely-not-a-real-route")
    assert resp.status_code == 401
