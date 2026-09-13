from __future__ import annotations

import json

import pytest

from bundlebleed.auth.cookies import parse_cookie_file, parse_cookie_text


def test_parse_raw_header_passthrough() -> None:
    assert parse_cookie_text("session=abc123; csrf=xyz789") == "session=abc123; csrf=xyz789"


def test_parse_json_cookie_array() -> None:
    raw = json.dumps([{"name": "session", "value": "abc123"}, {"name": "csrf", "value": "xyz789"}])
    assert parse_cookie_text(raw) == "session=abc123; csrf=xyz789"


def test_parse_netscape_cookie_file() -> None:
    raw = (
        "# Netscape HTTP Cookie File\n"
        "example.com\tFALSE\t/\tFALSE\t0\tsession\tabc123\n"
        "example.com\tFALSE\t/\tFALSE\t0\tcsrf\txyz789\n"
    )
    assert parse_cookie_text(raw) == "session=abc123; csrf=xyz789"


def test_parse_empty_content_fails_loudly() -> None:
    with pytest.raises(ValueError, match="empty"):
        parse_cookie_text("   ")


def test_parse_malformed_json_fails_loudly() -> None:
    with pytest.raises(ValueError):
        parse_cookie_text('[{"name": "session"}]')  # missing "value"


def test_parse_cookie_file_reads_from_disk(tmp_path) -> None:  # type: ignore[no-untyped-def]
    path = tmp_path / "cookies.txt"
    path.write_text("session=abc123")
    assert parse_cookie_file(path) == "session=abc123"
