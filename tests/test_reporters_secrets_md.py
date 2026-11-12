from __future__ import annotations

from datetime import datetime

from bundlebleed.models import EntropySecret, ScanResult, Secret
from bundlebleed.reporters.secrets_md import render_secrets_md


def _base(**kwargs) -> ScanResult:
    return ScanResult(scan_run_id="run-1", started_at=datetime.now(), **kwargs)  # type: ignore[arg-type]


def test_sections_present() -> None:
    rendered = render_secrets_md(_base())
    assert "5.1" in rendered
    assert "5.2" in rendered


def test_warning_present() -> None:
    rendered = render_secrets_md(_base())
    assert "Handle with care" in rendered or "redacted" in rendered.lower()


def test_pattern_matched_secret_rendered() -> None:
    result = _base(
        secrets=[
            Secret(
                secret_type="aws_access_key",
                severity="critical",
                redacted_value="AKIA...XXX",
                partial_hash="a1b2c3d4",
                source_url="https://example.com/app.js",
            )
        ]
    )
    rendered = render_secrets_md(result)
    assert "aws_access_key" in rendered
    assert "critical" in rendered
    assert "AKIA...XXX" in rendered
    assert "a1b2c3d4" in rendered


def test_entropy_secret_rendered() -> None:
    result = _base(
        entropy_secrets=[
            EntropySecret(
                file="app.js",
                line=42,
                entropy_score=4.8,
                redacted_value="rPmX...XXX",
                partial_hash="ff001122",
                source_url="https://example.com/app.js",
            )
        ]
    )
    rendered = render_secrets_md(result)
    assert "4.80" in rendered or "4.8" in rendered
    assert "rPmX...XXX" in rendered
    assert "42" in rendered


def test_severity_sorted() -> None:
    result = _base(
        secrets=[
            Secret(
                secret_type="low_type", severity="low",
                redacted_value="x", partial_hash="x", source_url="https://example.com/a.js",
            ),
            Secret(
                secret_type="crit_type", severity="critical",
                redacted_value="y", partial_hash="y", source_url="https://example.com/b.js",
            ),
        ]
    )
    rendered = render_secrets_md(result)
    crit_pos = rendered.index("crit_type")
    low_pos = rendered.index("low_type")
    assert crit_pos < low_pos


def test_empty_result_no_error() -> None:
    rendered = render_secrets_md(_base())
    assert "None found" in rendered
