from __future__ import annotations

from datetime import datetime
from pathlib import Path

from bundlebleed.hypotheses.models import Hypothesis
from bundlebleed.models import FileAnalysis, ScanResult, Secret
from bundlebleed.reporters.html_dashboard import render_html, write_html_report


def _base_result(**kwargs: object) -> ScanResult:
    return ScanResult(scan_run_id="run-1", started_at=datetime.now(), **kwargs)  # type: ignore[arg-type]


def test_render_html_has_title_and_no_external_dependencies() -> None:
    rendered = render_html(_base_result())
    assert "<title>BundleBleed Scan Report</title>" in rendered
    assert "http://" not in rendered
    assert "https://" not in rendered
    assert "cdn." not in rendered


def test_render_html_embeds_scan_run_id_and_stat_tiles() -> None:
    result = _base_result(targets=["example.com"], collected_urls=["https://example.com/a.js"])
    rendered = render_html(result)
    assert "run-1" in rendered
    assert "example.com" in rendered
    assert "Targets" in rendered
    assert "URLs collected" in rendered


def test_render_html_never_leaks_raw_secret_value() -> None:
    result = _base_result(
        secrets=[
            Secret(
                secret_type="AWS Access Key",
                severity="critical",
                redacted_value="AKIA****MNOP",
                partial_hash="deadbeef",
                source_url="https://example.com/app.js",
            )
        ]
    )
    rendered = render_html(result)
    assert "AKIA****MNOP" in rendered
    assert "AKIAABCDEFGHIJKLMNOP" not in rendered


def test_render_html_embeds_hypotheses_for_client_side_rendering() -> None:
    result = _base_result(
        hypotheses=[
            Hypothesis(
                id="hyp-1",
                target_kind="endpoint",
                target_value="/api/v1/users/123",
                source_url="https://example.com/app.js",
                bug_classes=["IDOR"],
                evidence_chain=["Endpoint discovered via pattern 'rest_api_path'"],
                confidence=0.7,
                risk="high",
                proposed_test="Compare responses across two low-privilege accounts.",
            )
        ]
    )
    rendered = render_html(result)
    assert "hyp-1" in rendered
    assert "/api/v1/users/123" in rendered


def test_render_html_embeds_recovered_source_map_file() -> None:
    result = _base_result(
        files=[
            FileAnalysis(
                url="https://e.com/app.js (source map: src/secrets.ts)",
                recovered_from_source_map=True,
            )
        ]
    )
    rendered = render_html(result)
    assert "src/secrets.ts" in rendered
    assert "recovered_from_source_map" in rendered


def test_write_html_report_creates_file(tmp_path: Path) -> None:
    path = write_html_report(_base_result(), tmp_path)
    assert path.name == "scan-result.html"
    assert path.exists()
    assert "BundleBleed Scan Report" in path.read_text()
