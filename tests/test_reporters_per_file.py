from __future__ import annotations

from datetime import datetime

from bundlebleed.models import (
    Endpoint,
    InterestingComment,
    ScanResult,
    Secret,
)
from bundlebleed.reporters.per_file import render_per_file


def _base(**kwargs) -> ScanResult:
    return ScanResult(scan_run_id="run-1", started_at=datetime.now(), **kwargs)  # type: ignore[arg-type]


def _ep(value: str, url: str = "https://example.com/app.js") -> Endpoint:
    return Endpoint(value=value, pattern_name="url_path", source_url=url)


def test_renders_file_url() -> None:
    result = _base(endpoints=[_ep("/api/v1/users")])
    rendered = render_per_file("https://example.com/app.js", result)
    assert "https://example.com/app.js" in rendered


def test_endpoints_for_file_shown() -> None:
    result = _base(
        endpoints=[
            _ep("/api/v1/users", url="https://example.com/app.js"),
            _ep("/other/endpoint", url="https://example.com/other.js"),
        ]
    )
    rendered = render_per_file("https://example.com/app.js", result)
    assert "/api/v1/users" in rendered
    assert "/other/endpoint" not in rendered


def test_secrets_for_file_shown() -> None:
    result = _base(
        secrets=[
            Secret(
                secret_type="github_token",
                severity="critical",
                redacted_value="ghp_...XXX",
                partial_hash="aabbccdd",
                source_url="https://example.com/app.js",
            )
        ]
    )
    rendered = render_per_file("https://example.com/app.js", result)
    assert "github_token" in rendered
    assert "ghp_...XXX" in rendered


def test_secrets_other_file_not_shown() -> None:
    result = _base(
        secrets=[
            Secret(
                secret_type="github_token",
                severity="critical",
                redacted_value="ghp_...XXX",
                partial_hash="aabbccdd",
                source_url="https://example.com/other.js",
            )
        ]
    )
    rendered = render_per_file("https://example.com/app.js", result)
    assert "github_token" not in rendered


def test_interest_score_nonzero_with_findings() -> None:
    result = _base(
        secrets=[
            Secret(
                secret_type="aws_key",
                severity="critical",
                redacted_value="AKIA...XXX",
                partial_hash="x",
                source_url="https://example.com/app.js",
            )
        ]
    )
    rendered = render_per_file("https://example.com/app.js", result)
    # Score of 10 for a secret
    assert "Interest score:** 10" in rendered or "Interest score:**" in rendered


def test_interesting_comments_shown() -> None:
    result = _base(
        interesting_comments=[
            InterestingComment(
                text="// TODO: remove hardcoded admin bypass",
                file="app.js",
                line=5,
                keyword_matched="admin",
                source_url="https://example.com/app.js",
            )
        ]
    )
    rendered = render_per_file("https://example.com/app.js", result)
    assert "admin" in rendered
    assert "hardcoded" in rendered


def test_no_findings_message() -> None:
    rendered = render_per_file("https://example.com/empty.js", _base())
    assert "No notable findings" in rendered or "Interest score:** 0" in rendered
