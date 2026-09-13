from __future__ import annotations

from datetime import datetime
from pathlib import Path

from bundlebleed.models import (
    Endpoint,
    ParameterFinding,
    ScanResult,
    SubdomainFinding,
    ThirdPartyScript,
)
from bundlebleed.reporters.wordlists import write_wordlists


def _base_result(**kwargs: object) -> ScanResult:
    return ScanResult(scan_run_id="run-1", started_at=datetime.now(), **kwargs)  # type: ignore[arg-type]


def test_write_wordlists_creates_all_five_files(tmp_path: Path) -> None:
    paths = write_wordlists(_base_result(), tmp_path)

    assert set(paths) == {
        "urls",
        "endpoints",
        "parameters",
        "subdomains",
        "third_party_hosts",
    }
    for path in paths.values():
        assert path.parent == tmp_path / "wordlists"
        assert path.exists()


def test_write_wordlists_writes_one_url_per_line(tmp_path: Path) -> None:
    result = _base_result(collected_urls=["https://example.com/b.js", "https://example.com/a.js"])
    paths = write_wordlists(result, tmp_path)
    lines = paths["urls"].read_text().splitlines()
    # sorted + deduped by ScanResult.normalized()
    assert lines == ["https://example.com/a.js", "https://example.com/b.js"]


def test_write_wordlists_dedupes_endpoint_values(tmp_path: Path) -> None:
    result = _base_result(
        endpoints=[
            Endpoint(value="/api/v1/users", pattern_name="rest_api_path", source_url="https://a"),
            Endpoint(value="/api/v1/users", pattern_name="fetch_call", source_url="https://b"),
        ]
    )
    paths = write_wordlists(result, tmp_path)
    assert paths["endpoints"].read_text().splitlines() == ["/api/v1/users"]


def test_write_wordlists_dedupes_parameter_names(tmp_path: Path) -> None:
    result = _base_result(
        parameters=[
            ParameterFinding(name="userId", source_url="https://a"),
            ParameterFinding(name="userId", source_url="https://b"),
        ]
    )
    paths = write_wordlists(result, tmp_path)
    assert paths["parameters"].read_text().splitlines() == ["userId"]


def test_write_wordlists_subdomains_excludes_flagged_for_review(tmp_path: Path) -> None:
    result = _base_result(
        subdomains=[
            SubdomainFinding(
                domain="api.example.com", source_url="https://a", in_scope=True, note=""
            ),
            SubdomainFinding(
                domain="suspicious.example.com",
                source_url="https://a",
                in_scope=False,
                note="flagged for manual review",
            ),
        ]
    )
    paths = write_wordlists(result, tmp_path)
    lines = paths["subdomains"].read_text().splitlines()
    assert lines == ["api.example.com"]
    assert "suspicious.example.com" not in lines


def test_write_wordlists_third_party_hosts_dedupes(tmp_path: Path) -> None:
    result = _base_result(
        third_party_scripts=[
            ThirdPartyScript(
                hostname="cdn.jsdelivr.net",
                script_url="https://cdn.jsdelivr.net/a.js",
                page_url="https://e.com/",
            ),
            ThirdPartyScript(
                hostname="cdn.jsdelivr.net",
                script_url="https://cdn.jsdelivr.net/b.js",
                page_url="https://e.com/other",
            ),
        ]
    )
    paths = write_wordlists(result, tmp_path)
    assert paths["third_party_hosts"].read_text().splitlines() == ["cdn.jsdelivr.net"]


def test_write_wordlists_handles_empty_result_without_error(tmp_path: Path) -> None:
    paths = write_wordlists(_base_result(), tmp_path)
    for path in paths.values():
        assert path.read_text() == ""
