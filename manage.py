"""User management CLI.

Usage:
  python manage.py list
  python manage.py add <username> [password]
  python manage.py passwd <username> [new-password]
  python manage.py delete <username>

If password is omitted, you'll be prompted (hidden input).
"""
import getpass
import sys

import bcrypt
from sqlalchemy import select

from db import SessionLocal, User, init_db


def hash_password(password: str) -> bytes:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())


def prompt_password(confirm: bool = True) -> str:
    pw = getpass.getpass("Password: ")
    if not pw:
        sys.exit("Password cannot be empty.")
    if confirm:
        again = getpass.getpass("Confirm:  ")
        if pw != again:
            sys.exit("Passwords do not match.")
    return pw


def cmd_list() -> None:
    with SessionLocal() as db:
        users = db.scalars(select(User).order_by(User.id)).all()
        if not users:
            print("(no users)")
            return
        for u in users:
            print(f"{u.id:>3}  {u.username:<24}  created {u.created_at:%Y-%m-%d %H:%M}")


def cmd_add(username: str, password: str | None) -> None:
    with SessionLocal() as db:
        if db.scalar(select(User).where(User.username == username)):
            sys.exit(f"User '{username}' already exists.")
        if password is None:
            password = prompt_password()
        db.add(User(username=username, password_hash=hash_password(password)))
        db.commit()
        print(f"Added user: {username}")


def cmd_passwd(username: str, password: str | None) -> None:
    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.username == username))
        if not user:
            sys.exit(f"User '{username}' not found.")
        if password is None:
            password = prompt_password()
        user.password_hash = hash_password(password)
        db.commit()
        print(f"Password updated for: {username}")


def cmd_delete(username: str) -> None:
    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.username == username))
        if not user:
            sys.exit(f"User '{username}' not found.")
        db.delete(user)
        db.commit()
        print(f"Deleted user: {username}")


def main() -> None:
    init_db()
    args = sys.argv[1:]
    if not args:
        sys.exit(__doc__)

    cmd, *rest = args
    if cmd == "list":
        cmd_list()
    elif cmd == "add":
        if not rest:
            sys.exit("Usage: python manage.py add <username> [password]")
        cmd_add(rest[0], rest[1] if len(rest) > 1 else None)
    elif cmd == "passwd":
        if not rest:
            sys.exit("Usage: python manage.py passwd <username> [new-password]")
        cmd_passwd(rest[0], rest[1] if len(rest) > 1 else None)
    elif cmd == "delete":
        if len(rest) != 1:
            sys.exit("Usage: python manage.py delete <username>")
        cmd_delete(rest[0])
    else:
        sys.exit(f"Unknown command: {cmd}\n\n{__doc__}")


if __name__ == "__main__":
    main()
