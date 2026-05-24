#!/usr/bin/env python3
"""Add or overwrite a user in auth/users.yaml.

Usage:
    python3 add_user.py <username>            # prompts for password (getpass)
    python3 add_user.py <username> <path>     # custom users.yaml path

Inside the api container the path defaults to /app/auth/users.yaml.
On the host it defaults to the auth/users.yaml next to this script.
"""

import argparse
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
VALID_ROLES = ("viewer", "operator", "admin")


def main() -> int:
    parser = argparse.ArgumentParser(description="Add or update a w4rya user.")
    parser.add_argument("username")
    parser.add_argument(
        "--role",
        default="viewer",
        choices=VALID_ROLES,
        help="permission tier (default: viewer)",
    )
    parser.add_argument("--path", default=DEFAULT_PATH, help="users.yaml path")
    args = parser.parse_args()

    if not USERNAME_RE.match(args.username):
        print("username must match [A-Za-z0-9_-]{1,32}", file=sys.stderr)
        return 2

    password = getpass.getpass(f"password for {args.username}: ")
    confirm = getpass.getpass("confirm:                ")
    if password != confirm:
        print("passwords don't match", file=sys.stderr)
        return 2
    if not password:
        print("empty password not allowed", file=sys.stderr)
        return 2

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(12)).decode()

    data: dict = {}
    if os.path.exists(args.path):
        with open(args.path) as f:
            data = yaml.safe_load(f) or {}

    users = data.setdefault("users", {}) or {}
    if args.username in users:
        print(
            f"note: user '{args.username}' already exists; overwriting hash + role",
            file=sys.stderr,
        )
    users[args.username] = {"password_hash": hashed, "role": args.role}
    data["users"] = users

    os.makedirs(os.path.dirname(args.path) or ".", exist_ok=True)
    with open(args.path, "w") as f:
        yaml.safe_dump(data, f, default_flow_style=False, sort_keys=True)

    print(f"wrote {args.path} — user '{args.username}' role={args.role} ({len(users)} user(s) total)")
    print("next: docker compose restart api")
    return 0


if __name__ == "__main__":
    sys.exit(main())
