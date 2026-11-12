from __future__ import annotations

from datetime import datetime

from bundlebleed.history.diff import compute_scan_diff
from bundlebleed.models import Endpoint, ScanResult, Secret, SubdomainFinding


def _result(**kwargs: object) -> ScanResult:
    return ScanResult(scan_run_id="run", started_at=datetime.now(), **kwargs)  # type: ignore[arg-type]


def _endpoint(value: str, source_url: str = "https://e.com/app.js") -> Endpoint:
    return Endpoint(value=value, pattern_name="rest_api_path", source_url=source_url)


def _secret(secret_type: str, partial_hash: str) -> Secret:
    return Secret(
        secret_type=secret_type,
        severity="high",
        redacted_value="x***y",
        partial_hash=partial_hash,
        source_url="https://e.com/app.js",
    )


def test_new_and_removed_endpoints() -> None:
    previous = _result(endpoints=[_endpoint("/api/a"), _endpoint("/api/b")])
    current = _result(endpoints=[_endpoint("/api/b"), _endpoint("/api/c")])

    diff = compute_scan_diff(previous, current)

    assert diff.new_endpoints == ["/api/c"]
    assert diff.removed_endpoints == ["/api/a"]


def test_new_and_removed_secrets() -> None:
    previous = _result(secrets=[_secret("aws_access_key", "hash1")])
    current = _result(secrets=[_secret("aws_access_key", "hash2")])

    diff = compute_scan_diff(previous, current)

    assert diff.new_secrets == ["aws_access_key:hash2"]
    assert diff.removed_secrets == ["aws_access_key:hash1"]


def test_new_and_removed_subdomains() -> None:
    previous = _result(
        subdomains=[
            SubdomainFinding(
                domain="old.e.com", source_url="https://e.com/app.js", in_scope=True, note="x"
            )
        ]
    )
    current = _result(
        subdomains=[
            SubdomainFinding(
                domain="new.e.com", source_url="https://e.com/app.js", in_scope=True, note="x"
            )
        ]
    )

    diff = compute_scan_diff(previous, current)

    assert diff.new_subdomains == ["new.e.com"]
    assert diff.removed_subdomains == ["old.e.com"]


def test_no_changes_produces_empty_diff() -> None:
    result = _result(endpoints=[_endpoint("/api/a")])
    diff = compute_scan_diff(result, result)
    assert diff.new_endpoints == []
    assert diff.removed_endpoints == []


def test_access_control_regression_detected() -> None:
    """An endpoint only reachable via an authenticated bundle last time, now
    reachable from an unauthenticated one: a real regression."""
    previous = _result(
        endpoints=[_endpoint("/api/admin/users/1", source_url="https://e.com/admin.js")],
        auth_only_js_urls=["https://e.com/admin.js"],
    )
    current = _result(
        endpoints=[_endpoint("/api/admin/users/1", source_url="https://e.com/public.js")],
        auth_only_js_urls=[],  # no longer behind auth
    )

    diff = compute_scan_diff(previous, current)

    assert diff.access_control_regressions == ["/api/admin/users/1"]


def test_no_regression_when_endpoint_stays_auth_gated() -> None:
    previous = _result(
        endpoints=[_endpoint("/api/admin/users/1", source_url="https://e.com/admin.js")],
        auth_only_js_urls=["https://e.com/admin.js"],
    )
    current = _result(
        endpoints=[_endpoint("/api/admin/users/1", source_url="https://e.com/admin2.js")],
        auth_only_js_urls=["https://e.com/admin2.js"],
    )

    diff = compute_scan_diff(previous, current)

    assert diff.access_control_regressions == []


def test_diff_carries_previous_scan_metadata() -> None:
    previous = _result()
    current = _result()
    diff = compute_scan_diff(previous, current)
    assert diff.previous_scan_run_id == "run"
    assert diff.previous_started_at == previous.started_at
