#!/usr/bin/env python3
"""Add or overwrite a user in auth/users.yaml.

Usage:
    python3 add_user.py <username>            # prompts for password (getpass)
    python3 add_user.py <username> <path>     # custom users.yaml path

Inside the api container the path defaults to /app/auth/users.yaml.
On the host it defaults to the auth/users.yaml next to this script.
"""

import getpass
import os
import re
import sys

import bcrypt
import yaml

DEFAULT_PATH = os.environ.get(
    "W4RYA_USERS_FILE",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.yaml"),
)

USERNAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: add_user.py <username> [users.yaml path]", file=sys.stderr)
        return 2

    username = sys.argv[1]
    path = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_PATH

    if not USERNAME_RE.match(username):
        print("username must match [A-Za-z0-9_-]{1,32}", file=sys.stderr)
        return 2

    password = getpass.getpass(f"password for {username}: ")
    confirm = getpass.getpass("confirm:                ")
    if password != confirm:
        print("passwords don't match", file=sys.stderr)
        return 2
    if not password:
        print("empty password not allowed", file=sys.stderr)
        return 2

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(12)).decode()

    data: dict = {}
    if os.path.exists(path):
        with open(path) as f:
            data = yaml.safe_load(f) or {}

    users = data.setdefault("users", {}) or {}
    if username in users:
        print(f"note: user '{username}' already exists; overwriting hash", file=sys.stderr)
    users[username] = {"password_hash": hashed}
    data["users"] = users

    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as f:
        yaml.safe_dump(data, f, default_flow_style=False, sort_keys=True)

    print(f"wrote {path} ({len(users)} user(s) total)")
    print("next: docker compose restart api")
    return 0


if __name__ == "__main__":
    sys.exit(main())
