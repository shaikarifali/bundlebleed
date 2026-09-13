from __future__ import annotations

import pytest

from bundlebleed.auth.models import AuthSession
from bundlebleed.auth.parser import load_auth_sessions_from_scope_yaml, parse_session_arg


def test_auth_session_repr_never_leaks_cookie_value() -> None:
    session = AuthSession(name="admin", role="admin", cookie_header="session=super-secret-token")
    rendered = repr(session)
    assert "super-secret-token" not in rendered
    assert "redacted" in rendered


def test_auth_session_str_uses_repr_and_stays_redacted() -> None:
    session = AuthSession(name="admin", role="admin", cookie_header="session=super-secret-token")
    assert "super-secret-token" not in str(session)


def test_parse_session_arg_splits_name_and_cookie() -> None:
    session = parse_session_arg("admin:session=abc123; csrf=xyz")
    assert session.name == "admin"
    assert session.role == "admin"
    assert session.cookie_header == "session=abc123; csrf=xyz"


def test_parse_session_arg_requires_colon_separator() -> None:
    with pytest.raises(ValueError, match="name:cookie_string"):
        parse_session_arg("no-colon-here")


def test_parse_session_arg_requires_non_empty_parts() -> None:
    with pytest.raises(ValueError):
        parse_session_arg(":session=abc123")
    with pytest.raises(ValueError):
        parse_session_arg("admin:")


def test_load_auth_sessions_from_scope_yaml_reads_sessions(tmp_path) -> None:  # type: ignore[no-untyped-def]
    scope_file = tmp_path / "scope.yaml"
    scope_file.write_text(
        "scope:\n"
        "  in_scope:\n"
        "    - domain: example.com\n"
        "      type: exact\n"
        "auth:\n"
        "  sessions:\n"
        "    - name: user\n"
        "      cookies: 'session=abc123'\n"
        "      role: user\n"
        "    - name: admin\n"
        "      cookies: 'session=def456'\n"
    )
    sessions = load_auth_sessions_from_scope_yaml(scope_file)

    assert len(sessions) == 2
    assert sessions[0].name == "user"
    assert sessions[0].role == "user"
    assert sessions[0].cookie_header == "session=abc123"
    assert sessions[1].name == "admin"
    assert sessions[1].role == "admin"  # defaults to name when role omitted


def test_load_auth_sessions_from_scope_yaml_falls_back_to_cookie_file(tmp_path) -> None:  # type: ignore[no-untyped-def]
    cookie_file = tmp_path / "cookies.json"
    cookie_file.write_text('[{"name": "session", "value": "abc123"}]')
    scope_file = tmp_path / "scope.yaml"
    scope_file.write_text(
        "scope:\n"
        "  in_scope:\n"
        "    - domain: example.com\n"
        "      type: exact\n"
        "auth:\n"
        "  cookie_file: cookies.json\n"
    )
    sessions = load_auth_sessions_from_scope_yaml(scope_file)

    assert len(sessions) == 1
    assert sessions[0].cookie_header == "session=abc123"


def test_load_auth_sessions_from_scope_yaml_no_auth_section_returns_empty(tmp_path) -> None:  # type: ignore[no-untyped-def]
    scope_file = tmp_path / "scope.yaml"
    scope_file.write_text("scope:\n  in_scope:\n    - domain: example.com\n      type: exact\n")
    assert load_auth_sessions_from_scope_yaml(scope_file) == []
