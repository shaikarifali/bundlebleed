from __future__ import annotations

from bundlebleed.extractors.cors import extract_cors_misconfiguration


def test_flags_wildcard_origin_with_credentials_true() -> None:
    headers = {"access-control-allow-origin": "*", "access-control-allow-credentials": "true"}
    finding = extract_cors_misconfiguration(headers, "https://api.example.com/me")
    assert finding is not None
    assert finding.allow_origin == "*"
    assert finding.allow_credentials is True
    assert finding.source_url == "https://api.example.com/me"


def test_wildcard_without_credentials_is_not_flagged() -> None:
    # A bare wildcard ACAO with no credentials flag is a normal, safe public API.
    headers = {"access-control-allow-origin": "*"}
    assert extract_cors_misconfiguration(headers, "x") is None


def test_specific_origin_with_credentials_is_not_flagged() -> None:
    # Allowing one specific configured origin with credentials is a
    # legitimate, common pattern -- only the wildcard+credentials
    # combination is unambiguously invalid.
    headers = {
        "access-control-allow-origin": "https://app.example.com",
        "access-control-allow-credentials": "true",
    }
    assert extract_cors_misconfiguration(headers, "x") is None


def test_no_cors_headers_is_not_flagged() -> None:
    assert extract_cors_misconfiguration({}, "x") is None


def test_credentials_header_is_case_insensitive() -> None:
    headers = {"access-control-allow-origin": "*", "access-control-allow-credentials": "TRUE"}
    assert extract_cors_misconfiguration(headers, "x") is not None
