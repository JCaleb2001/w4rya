"""Admin user management over HTTP — the path the team actually uses to get
their own logins once the installer has made the first admin."""

import user_store


def test_admin_lists_users_without_hashes(admin):
    resp = admin.get("/users")
    assert resp.status_code == 200
    for row in resp.get_json():
        assert set(row) == {"username", "role"}


def test_admin_creates_a_teammate(admin):
    resp = admin.post("/users", json={
        "username": "bob", "password": "bobs-password", "role": "operator",
    })
    assert resp.status_code == 201
    assert resp.get_json() == {"username": "bob", "role": "operator"}
    assert {u["username"] for u in user_store.list_users()} >= {"bob"}


def test_created_teammate_can_log_in_with_their_own_account(admin, app):
    admin.post("/users", json={
        "username": "bob", "password": "bobs-password", "role": "operator",
    })
    bob = app.test_client()
    resp = bob.post("/login", json={"username": "bob", "password": "bobs-password"})
    assert resp.status_code == 200
    assert resp.get_json() == {"user": "bob", "role": "operator"}


def test_new_accounts_default_to_the_least_privilege(admin):
    resp = admin.post("/users", json={"username": "bob", "password": "bobs-password"})
    assert resp.status_code == 201
    assert resp.get_json()["role"] == "viewer"


def test_duplicate_and_invalid_input_are_rejected(admin):
    admin.post("/users", json={"username": "bob", "password": "bobs-password", "role": "viewer"})
    assert admin.post("/users", json={
        "username": "bob", "password": "another-password", "role": "viewer",
    }).status_code == 409
    assert admin.post("/users", json={
        "username": "bob2", "password": "bobs-password", "role": "root",
    }).status_code == 400
    assert admin.post("/users", json={"username": "bob3", "password": "sh"}).status_code == 400


def test_role_can_be_changed(admin):
    admin.post("/users", json={"username": "bob", "password": "bobs-password", "role": "viewer"})
    resp = admin.put("/users/bob/role", json={"role": "operator"})
    assert resp.status_code == 200
    assert resp.get_json() == {"username": "bob", "role": "operator"}


def test_password_rotation_invalidates_the_old_one(admin, app):
    admin.post("/users", json={"username": "bob", "password": "bobs-password", "role": "viewer"})
    assert admin.put("/users/bob/password", json={"password": "new-password-9"}).status_code == 200
    client = app.test_client()
    assert client.post("/login", json={"username": "bob", "password": "bobs-password"}).status_code == 401
    assert client.post("/login", json={"username": "bob", "password": "new-password-9"}).status_code == 200


def test_deletion_works_for_a_normal_account(admin):
    admin.post("/users", json={"username": "bob", "password": "bobs-password", "role": "viewer"})
    assert admin.delete("/users/bob").status_code == 200
    assert "bob" not in {u["username"] for u in user_store.list_users()}


def test_you_cannot_delete_the_account_you_are_signed_in_as(admin):
    resp = admin.delete("/users/admin_user")
    assert resp.status_code == 409
    assert "signed in as" in resp.get_json()["error"]


def test_the_last_admin_is_protected(admin, app):
    """Deleting or demoting the only admin would lock the whole team out of
    /config and /audit with no way back except editing users.yaml by hand."""
    admin.post("/users", json={"username": "bob", "password": "bobs-password", "role": "operator"})
    # A second admin exists only after we make one, so until then both are refused.
    assert admin.put("/users/admin_user/role", json={"role": "viewer"}).status_code == 409

    admin.post("/users", json={"username": "ana", "password": "anas-password", "role": "admin"})
    assert admin.put("/users/admin_user/role", json={"role": "viewer"}).status_code == 200


def test_missing_user_is_a_404(admin):
    assert admin.delete("/users/ghost").status_code == 404
    assert admin.put("/users/ghost/role", json={"role": "viewer"}).status_code == 404
    assert admin.put("/users/ghost/password", json={"password": "longenough1"}).status_code == 404
