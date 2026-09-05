"""Tests for user_store — validation, the self-closing first-run path, the
last-admin guards, and the cross-worker race that motivated the file lock.

No DB and no Flask app: user_store only touches the filesystem.
"""

import threading

import pytest

import user_store


@pytest.fixture(autouse=True)
def store(tmp_path, monkeypatch):
    """Point the store at a throwaway users.yaml and make bcrypt cheap.

    12 rounds is right in production and far too slow to run dozens of times
    in a unit suite.
    """
    monkeypatch.setattr(user_store, "USERS_FILE", str(tmp_path / "users.yaml"))
    monkeypatch.setattr(user_store, "BCRYPT_ROUNDS", 4)
    return tmp_path


def err(fn, *a, **kw):
    with pytest.raises(user_store.UserStoreError) as ei:
        fn(*a, **kw)
    return ei.value


# --- validation ---

@pytest.mark.parametrize("bad", ["", "  ", "a" * 33, "has space", "sí", "a;b", "../x"])
def test_username_rejected(bad):
    assert err(user_store.validate_username, bad).code == 400


@pytest.mark.parametrize("ok", ["caleb", "a", "A-b_9", "x" * 32])
def test_username_accepted(ok):
    assert user_store.validate_username(ok) == ok


def test_username_is_trimmed():
    assert user_store.validate_username("  caleb  ") == "caleb"


def test_password_minimum_enforced():
    assert err(user_store.validate_password, "short").code == 400
    assert err(user_store.validate_password, "").code == 400
    assert user_store.validate_password("longenough")


def test_role_must_be_known():
    assert err(user_store.validate_role, "root").code == 400
    assert err(user_store.validate_role, "").code == 400


def test_hash_roundtrip():
    import bcrypt
    h = user_store.hash_password("correct horse")
    assert bcrypt.checkpw(b"correct horse", h.encode())
    assert not bcrypt.checkpw(b"wrong horse", h.encode())


# --- empty store ---

def test_missing_file_reads_as_empty():
    assert user_store.count() == 0
    assert user_store.users_exist() is False
    assert user_store.list_users() == []


def test_unparseable_file_is_never_overwritten(store):
    (store / "users.yaml").write_text("users: [this is: not, a mapping\n")
    # Refusing here is the point: silently rewriting would drop every account.
    assert err(user_store.count).code == 500


# --- first-run path ---

def test_first_user_created_as_admin():
    created = user_store.create_user("caleb", "hunter2hunter2", "admin", only_if_empty=True)
    assert created == {"username": "caleb", "role": "admin"}
    assert user_store.users_exist() is True


def test_setup_closes_itself():
    user_store.create_user("caleb", "hunter2hunter2", "admin", only_if_empty=True)
    e = err(user_store.create_user, "mallory", "hunter2hunter2", "admin", only_if_empty=True)
    assert e.code == 409
    assert [u["username"] for u in user_store.list_users()] == ["caleb"]


def test_setup_race_produces_exactly_one_admin():
    """Two gunicorn workers POSTing /setup at once must not both win."""
    winners, losers = [], []
    barrier = threading.Barrier(8)

    def attempt(i):
        barrier.wait()
        try:
            winners.append(user_store.create_user(
                f"user{i}", "hunter2hunter2", "admin", only_if_empty=True))
        except user_store.UserStoreError as e:
            losers.append(e.code)

    threads = [threading.Thread(target=attempt, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(winners) == 1, f"expected 1 winner, got {len(winners)}"
    assert losers == [409] * 7
    assert user_store.count() == 1


# --- normal creation ---

def test_duplicate_rejected_but_overwrite_allowed():
    user_store.create_user("caleb", "hunter2hunter2", "admin")
    assert err(user_store.create_user, "caleb", "otherpassword", "viewer").code == 409
    user_store.create_user("caleb", "otherpassword", "viewer", overwrite=True)
    assert user_store.list_users() == [{"username": "caleb", "role": "viewer"}]


def test_list_users_never_leaks_hashes():
    user_store.create_user("caleb", "hunter2hunter2", "admin")
    for row in user_store.list_users():
        assert set(row) == {"username", "role"}


def test_legacy_entry_without_role_reads_as_admin(store):
    (store / "users.yaml").write_text(
        'users:\n  old:\n    password_hash: "$2b$04$abcdefghijklmnopqrstuv"\n'
    )
    assert user_store.list_users() == [{"username": "old", "role": "admin"}]


# --- last-admin guards ---

def test_cannot_delete_last_admin():
    user_store.create_user("caleb", "hunter2hunter2", "admin")
    user_store.create_user("bob", "hunter2hunter2", "operator")
    assert err(user_store.delete_user, "caleb").code == 409
    user_store.delete_user("bob")  # non-admin goes fine
    assert user_store.count() == 1


def test_cannot_demote_last_admin():
    user_store.create_user("caleb", "hunter2hunter2", "admin")
    assert err(user_store.set_role, "caleb", "viewer").code == 409


def test_second_admin_unlocks_the_guard():
    user_store.create_user("caleb", "hunter2hunter2", "admin")
    user_store.create_user("ana", "hunter2hunter2", "admin")
    user_store.set_role("caleb", "viewer")
    assert {u["username"]: u["role"] for u in user_store.list_users()} == {
        "caleb": "viewer", "ana": "admin",
    }


def test_delete_and_role_need_an_existing_user():
    assert err(user_store.delete_user, "ghost").code == 404
    assert err(user_store.set_role, "ghost", "viewer").code == 404
    assert err(user_store.set_password, "ghost", "hunter2hunter2").code == 404


def test_set_password_keeps_role_and_changes_hash(store):
    import bcrypt
    import yaml
    user_store.create_user("caleb", "hunter2hunter2", "operator")
    before = yaml.safe_load((store / "users.yaml").read_text())["users"]["caleb"]
    user_store.set_password("caleb", "brandnewpassword")
    after = yaml.safe_load((store / "users.yaml").read_text())["users"]["caleb"]
    assert after["role"] == "operator" == before["role"]
    assert after["password_hash"] != before["password_hash"]
    assert bcrypt.checkpw(b"brandnewpassword", after["password_hash"].encode())


def test_write_is_atomic_and_leaves_no_temp_files(store):
    user_store.create_user("caleb", "hunter2hunter2", "admin")
    user_store.create_user("ana", "hunter2hunter2", "viewer")
    leftovers = [p.name for p in store.iterdir() if p.name.startswith(".users.")]
    assert leftovers == []
