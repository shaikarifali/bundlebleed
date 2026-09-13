from __future__ import annotations

import json

import pytest

from bundlebleed.scope.guard import ScopeGuard
from bundlebleed.scope.models import Decision
from bundlebleed.scope.parser import parse_scope_txt_file, parse_scope_yaml_file
from tests.conftest import FIXTURES_DIR

BASIC = FIXTURES_DIR / "scope-samples" / "basic.txt"
FULL = FIXTURES_DIR / "scope-samples" / "full.yaml"


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com/",
        "https://sub.example.com/x",
        "https://deep.sub.example.com/y",
        "https://api.example.com/foo",
        "example.com",
    ],
)
def test_should_match_in_scope(url: str) -> None:
    config = parse_scope_txt_file(BASIC)
    guard = ScopeGuard(config)
    decision = guard.check(url)
    assert decision.decision == Decision.ALLOW, decision.reason


@pytest.mark.parametrize(
    "url",
    [
        "https://blog.example.com/",
        "https://notinscope.com/",
        "https://foo.wordpress.example.com/",
        "https://evil-example.com/",
    ],
)
def test_should_not_match_out_of_scope(url: str) -> None:
    config = parse_scope_txt_file(BASIC)
    guard = ScopeGuard(config)
    decision = guard.check(url)
    assert decision.decision == Decision.DENY


def test_excluded_path_denies_even_when_domain_in_scope() -> None:
    config = parse_scope_yaml_file(FULL)
    guard = ScopeGuard(config)

    allowed = guard.check("https://example.com/dashboard")
    assert allowed.decision == Decision.ALLOW

    denied = guard.check("https://example.com/api/v1/payment/charge")
    assert denied.decision == Decision.DENY
    assert "excluded path" in denied.reason

    denied_checkout = guard.check("https://example.com/checkout/cart")
    assert denied_checkout.decision == Decision.DENY


def test_out_of_scope_overrides_wildcard_in_scope() -> None:
    config = parse_scope_yaml_file(FULL)
    guard = ScopeGuard(config)
    decision = guard.check("https://blog.example.com/post/1")
    assert decision.decision == Decision.DENY
    assert "out-of-scope" in decision.reason


def test_every_decision_is_audited(tmp_path) -> None:  # type: ignore[no-untyped-def]
    config = parse_scope_txt_file(BASIC)
    audit_path = tmp_path / "audit_log.jsonl"
    guard = ScopeGuard(config, audit_log_path=audit_path, scan_run_id="run-123")

    guard.check("https://example.com/")
    guard.check("https://notinscope.com/")

    rows = [json.loads(line) for line in audit_path.read_text().splitlines()]
    assert len(rows) == 2
    assert rows[0]["decision"] == "ALLOW"
    assert rows[0]["scan_run_id"] == "run-123"
    assert rows[1]["decision"] == "DENY"


def test_filter_allowed_keeps_only_allowed_urls() -> None:
    config = parse_scope_txt_file(BASIC)
    guard = ScopeGuard(config)
    urls = ["https://example.com/a", "https://blog.example.com/b", "https://notinscope.com/c"]
    assert guard.filter_allowed(urls) == ["https://example.com/a"]
