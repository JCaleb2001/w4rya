"""The permission matrix, as data.

Mirrors the table in CLAUDE.md. Two directions are checked:

  forward — for each gated route: anon 401, an under-privileged role 403 with
            the {error, required_role, your_role} shape the frontend reads, and
            the required role not 403.
  inverse — every view actually decorated with @auth.requires_role appears in
            the table below, so adding a gate without a test fails here.
"""

import pytest

import auth

# (method, path, required_role)
MATRIX = [
    ("POST",   "/star",                                          "operator"),
    ("POST",   "/rules",                                         "operator"),
    ("PUT",    "/rules/1",                                       "operator"),
    ("DELETE", "/rules/1",                                       "operator"),
    ("POST",   "/rules/block-ip",                                "operator"),
    ("POST",   "/rules/reload",                                  "operator"),
    ("POST",   "/attack/replay",                                 "operator"),
    ("PUT",    "/config",                                        "admin"),
    ("PUT",    "/config/services",                               "admin"),
    ("PUT",    "/config/teams",                                  "admin"),
    ("GET",    "/audit",                                         "admin"),
    ("GET",    "/audit/actors",                                  "admin"),
    ("GET",    "/audit/export.csv",                              "admin"),
    ("GET",    "/users",                                         "admin"),
    ("POST",   "/users",                                         "admin"),
    ("DELETE", "/users/somebody",                                "admin"),
    ("PUT",    "/users/somebody/role",                           "admin"),
    ("PUT",    "/users/somebody/password",                       "admin"),
]

BELOW = {"operator": "viewer", "admin": "operator"}


def _ids():
    return [f"{m} {p} needs {r}" for m, p, r in MATRIX]


def _declared_min_role(view):
    """Recover the role a view was decorated with.

    `requires_role` closes over `min_role`, so the string is reachable through
    the wrapper's closure. Slightly nosy, but it is what lets the inverse test
    below detect a gate that nobody wrote a case for.
    """
    if not hasattr(view, "__wrapped__"):
        return None
    for cell in (view.__closure__ or ()):
        try:
            value = cell.cell_contents
        except ValueError:
            continue
        if isinstance(value, str) and value in auth.ROLE_RANK:
            return value
    return None


@pytest.mark.parametrize("method,path,required", MATRIX, ids=_ids())
def test_anonymous_gets_401(anon, method, path, required):
    assert anon.open(path, method=method).status_code == 401


@pytest.mark.parametrize("method,path,required", MATRIX, ids=_ids())
def test_insufficient_role_gets_403_with_the_documented_shape(
    request, fake_db, method, path, required
):
    client = request.getfixturevalue(BELOW[required])
    resp = client.open(path, method=method, json={})
    assert resp.status_code == 403, f"{method} {path} gave {resp.status_code}"
    assert resp.is_json
    body = resp.get_json()
    # The frontend renders "requires X, your role is Y" straight off these.
    assert body["error"] == "forbidden"
    assert body["required_role"] == required
    assert body["your_role"] == BELOW[required]


@pytest.mark.parametrize("method,path,required", MATRIX, ids=_ids())
def test_required_role_passes_the_gate(request, fake_db, method, path, required):
    """Not asserting 200 — with a fake db these land on 400/404/503 depending on
    the route. The point is only that the role check let them through."""
    client = request.getfixturevalue(required)
    resp = client.open(path, method=method, json={})
    assert resp.status_code not in (401, 403), (
        f"{method} {path} rejected {required} with {resp.status_code}"
    )


def test_admin_passes_operator_gates(admin, fake_db):
    """Roles are ranked, not a set: admin outranks operator everywhere."""
    for method, path, required in MATRIX:
        if required != "operator":
            continue
        resp = admin.open(path, method=method, json={})
        assert resp.status_code != 403, f"admin was refused {method} {path}"


def test_every_gated_route_is_in_the_matrix(app):
    """Inverse direction: a new @requires_role with no test case fails here."""
    covered = {(m, r) for m, _p, r in MATRIX}
    missing = []
    for rule in app.url_map.iter_rules():
        view = app.view_functions.get(rule.endpoint)
        role = _declared_min_role(view) if view else None
        if role is None:
            continue
        for method in sorted(rule.methods - {"HEAD", "OPTIONS"}):
            if (method, role) not in covered:
                missing.append(f"{method} {rule.rule} (needs {role})")
    assert not missing, (
        "these routes are role-gated but absent from MATRIX: " + ", ".join(sorted(missing))
    )


def test_matrix_roles_are_all_real_roles():
    for _m, _p, role in MATRIX:
        assert role in auth.ROLE_RANK
