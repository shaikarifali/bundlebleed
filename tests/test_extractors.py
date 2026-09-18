from __future__ import annotations

from bundlebleed.extractors.endpoints import deduplicate_endpoints, extract_endpoints
from bundlebleed.extractors.secrets import extract_secrets
from bundlebleed.models import Endpoint
from tests.conftest import FIXTURES_DIR

REACT_BUNDLE = (FIXTURES_DIR / "js" / "react_bundle.js").read_text()
CLEAN_BUNDLE = (FIXTURES_DIR / "js" / "clean_bundle.js").read_text()


def test_extract_endpoints_finds_expected_values() -> None:
    endpoints = extract_endpoints(REACT_BUNDLE, source_url="https://example.com/app.js")
    values = {e.value for e in endpoints}

    assert "/api/v1/users/" in values
    assert "/api/v2/orders/{id}" in values
    assert "/api/v1/reset" in values
    assert "/dashboard/:userId" in values

    for e in endpoints:
        assert e.source_url == "https://example.com/app.js"


def test_extract_endpoints_dedupes_same_pattern_and_value() -> None:
    content = 'fetch("/api/v1/users/1"); fetch("/api/v1/users/1");'
    endpoints = extract_endpoints(content, source_url="x")
    matching = [
        e for e in endpoints if e.value == "/api/v1/users/1" and e.pattern_name == "fetch_call"
    ]
    assert len(matching) == 1


def test_extract_endpoints_clean_bundle_finds_nothing() -> None:
    assert extract_endpoints(CLEAN_BUNDLE, source_url="https://example.com/clean.js") == []


def test_extract_secrets_finds_expected_types() -> None:
    secrets = extract_secrets(REACT_BUNDLE, source_url="https://example.com/app.js")
    types = {s.secret_type for s in secrets}
    assert types == {"aws_access_key", "stripe_live_key"}


def test_extract_secrets_never_returns_raw_value() -> None:
    secrets = extract_secrets(REACT_BUNDLE, source_url="https://example.com/app.js")
    for s in secrets:
        assert "AKIAABCDEFGHIJKLMNOP" not in s.redacted_value
        assert "sk_live_ABCDEFGHIJKLMNOPQRSTUVWX" not in s.redacted_value
        assert "*" in s.redacted_value
        assert len(s.partial_hash) == 12


def test_extract_secrets_clean_bundle_finds_nothing() -> None:
    assert extract_secrets(CLEAN_BUNDLE, source_url="https://example.com/clean.js") == []


def test_extract_secrets_dedupes_identical_matches() -> None:
    content = "key=AKIAABCDEFGHIJKLMNOP another=AKIAABCDEFGHIJKLMNOP"
    secrets = extract_secrets(content, source_url="x")
    assert len(secrets) == 1


def test_deduplicate_endpoints_merges_across_files_into_one() -> None:
    # The same endpoint referenced from two different webpack chunks used to
    # produce two separate Endpoints (and so two duplicate Hypotheses) --
    # deduplicate_endpoints() collapses them into one, keeping the first
    # file as primary and recording the rest as evidence.
    endpoints = [
        Endpoint(value="/api/v1/profile", pattern_name="fetch_call", source_url="chunk-a.js"),
        Endpoint(value="/api/v1/profile", pattern_name="fetch_call", source_url="chunk-b.js"),
        Endpoint(value="/api/v1/profile", pattern_name="fetch_call", source_url="chunk-c.js"),
    ]
    merged = deduplicate_endpoints(endpoints)
    assert len(merged) == 1
    assert merged[0].source_url == "chunk-a.js"
    assert merged[0].also_seen_in == ["chunk-b.js", "chunk-c.js"]


def test_deduplicate_endpoints_keeps_different_methods_separate() -> None:
    # Same URL, different verb -- a genuinely different endpoint, must not
    # be collapsed into one.
    endpoints = [
        Endpoint(
            value="/api/v1/orders/1",
            pattern_name="axios_call",
            source_url="a.js",
            method="GET",
        ),
        Endpoint(
            value="/api/v1/orders/1",
            pattern_name="axios_call",
            source_url="a.js",
            method="DELETE",
        ),
    ]
    merged = deduplicate_endpoints(endpoints)
    assert len(merged) == 2


def test_deduplicate_endpoints_preserves_first_seen_order() -> None:
    endpoints = [
        Endpoint(value="/b", pattern_name="fetch_call", source_url="x.js"),
        Endpoint(value="/a", pattern_name="fetch_call", source_url="x.js"),
        Endpoint(value="/b", pattern_name="fetch_call", source_url="y.js"),
    ]
    merged = deduplicate_endpoints(endpoints)
    assert [e.value for e in merged] == ["/b", "/a"]
