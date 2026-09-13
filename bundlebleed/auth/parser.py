from __future__ import annotations

from pathlib import Path

import yaml

from bundlebleed.auth.cookies import parse_cookie_file
from bundlebleed.auth.models import AuthSession


def parse_session_arg(raw: str) -> AuthSession:
    """Parse a `--session "name:cookie_string"` CLI argument."""
    name, sep, cookie_header = raw.partition(":")
    if not sep:
        raise ValueError("--session must be in the form 'name:cookie_string'")
    name = name.strip()
    cookie_header = cookie_header.strip()
    if not name or not cookie_header:
        raise ValueError("--session name and cookie string must both be non-empty")
    return AuthSession(name=name, role=name, cookie_header=cookie_header)


def load_auth_sessions_from_scope_yaml(path: Path) -> list[AuthSession]:
    """Read the `auth:` section from a full scope.yaml, independent of
    ScopeConfig — credential material is kept out of the object that gets
    passed around broadly and could accidentally be logged or serialized
    elsewhere. Supports `auth.sessions` (named sessions) and, when no
    sessions are given, a single `auth.cookie_file`.
    """
    raw = yaml.safe_load(path.read_text()) or {}
    auth_section = raw.get("auth") or {}

    sessions: list[AuthSession] = []
    for entry in auth_section.get("sessions", []):
        cookies = entry.get("cookies", "")
        if not cookies:
            continue
        name = entry["name"]
        role = entry.get("role", name)
        sessions.append(AuthSession(name=name, role=role, cookie_header=cookies))

    if not sessions and auth_section.get("cookie_file"):
        cookie_file_path = Path(auth_section["cookie_file"])
        if not cookie_file_path.is_absolute():
            cookie_file_path = path.parent / cookie_file_path
        cookie_header = parse_cookie_file(cookie_file_path)
        sessions.append(AuthSession(name="file", role="user", cookie_header=cookie_header))

    return sessions
