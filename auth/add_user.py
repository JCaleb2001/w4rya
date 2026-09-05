#!/usr/bin/env python3
"""Add or update a user in auth/users.yaml.

Usage:
    python3 add_user.py <username> [--role admin|operator|viewer]
    python3 add_user.py <username> --path /custom/users.yaml

Preferred invocation (deps are already installed in the api image):
    docker compose run --rm api python /app/auth/add_user.py <name> --role admin

Since v0.6.0 the UI has a first-run wizard and an admin Users page, so this
script is the escape hatch: bootstrapping without a browser, rotating a
password, or fixing a locked-out install. All the validation, hashing and
locking lives in services/api/user_store.py so the two paths cannot drift.
"""

import argparse
import getpass
import os
import sys

# user_store lives with the api code: /app inside the container, or
# ../services/api when this script is run straight from a checkout.
_HERE = os.path.dirname(os.path.abspath(__file__))
for _candidate in ("/app", os.path.join(os.path.dirname(_HERE), "services", "api")):
    if os.path.isfile(os.path.join(_candidate, "user_store.py")):
        sys.path.insert(0, _candidate)
        break

try:
    import user_store
except ImportError:
    print(
        "cannot import user_store — run this inside the api container:\n"
        "  docker compose run --rm api python /app/auth/add_user.py <name> --role admin",
        file=sys.stderr,
    )
    raise SystemExit(2)


def main() -> int:
    parser = argparse.ArgumentParser(description="Add or update a w4rya user.")
    parser.add_argument("username")
    parser.add_argument(
        "--role",
        default=user_store.VALID_ROLES[0],
        choices=user_store.VALID_ROLES,
        help="permission tier (default: viewer)",
    )
    parser.add_argument("--path", default=None, help="users.yaml path")
    parser.add_argument(
        "--stdin",
        action="store_true",
        help="read the password from stdin (one line) instead of prompting. "
             "Used by install.sh so the password never becomes argv or an env var.",
    )
    args = parser.parse_args()

    if args.path:
        user_store.USERS_FILE = args.path

    if args.stdin:
        # One line, newline stripped. No confirm loop: the caller already
        # confirmed it. Reading from a pipe would otherwise make getpass emit
        # "Warning: Password input may be echoed" and ask twice.
        password = sys.stdin.readline().rstrip("\n")
    else:
        password = getpass.getpass(f"password for {args.username}: ")
        confirm = getpass.getpass("confirm:                ")
        if password != confirm:
            print("passwords don't match", file=sys.stderr)
            return 2

    existed = args.username in {u["username"] for u in _safe_list()}
    if existed:
        print(
            f"note: user '{args.username}' already exists; overwriting hash + role",
            file=sys.stderr,
        )

    try:
        created = user_store.create_user(
            args.username, password, args.role, overwrite=True
        )
    except user_store.UserStoreError as e:
        print(e.message, file=sys.stderr)
        return 2

    total = len(_safe_list())
    print(
        f"wrote {user_store.USERS_FILE} — user '{created['username']}' "
        f"role={created['role']} ({total} user(s) total)"
    )
    print("next: docker compose restart api")
    return 0


def _safe_list() -> list:
    try:
        return user_store.list_users()
    except user_store.UserStoreError:
        return []


if __name__ == "__main__":
    raise SystemExit(main())
