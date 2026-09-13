from __future__ import annotations

from datetime import datetime

from bundlebleed.history.models import ScanDiff
from bundlebleed.monitoring.formatter import format_slack_payload, has_changes


def _diff(**overrides: object) -> ScanDiff:
    defaults: dict[str, object] = {
        "previous_scan_run_id": "run-1",
        "previous_started_at": datetime.now(),
    }
    defaults.update(overrides)
    return ScanDiff(**defaults)  # type: ignore[arg-type]


def test_has_changes_false_for_empty_diff() -> None:
    assert has_changes(_diff()) is False


def test_has_changes_true_for_new_endpoint() -> None:
    assert has_changes(_diff(new_endpoints=["/api/a"])) is True


def test_has_changes_true_for_regression_only() -> None:
    assert has_changes(_diff(access_control_regressions=["/api/admin"])) is True


def test_format_slack_payload_has_text_key() -> None:
    payload = format_slack_payload(_diff(new_endpoints=["/api/a"]), "example.com")
    assert "text" in payload
    assert "example.com" in payload["text"]


def test_format_slack_payload_mentions_regressions_prominently() -> None:
    payload = format_slack_payload(
        _diff(access_control_regressions=["/api/admin/users/1"]), "example.com"
    )
    assert "regression" in payload["text"].lower()
    assert "/api/admin/users/1" in payload["text"]


def test_format_slack_payload_never_includes_raw_secret_values() -> None:
    """The formatter only ever reports a secret *count* — never the
    type:partial_hash label, and certainly never a raw value."""
    payload = format_slack_payload(_diff(new_secrets=["aws_access_key:abc123"]), "example.com")
    assert "1 new secret" in payload["text"]
    assert "aws_access_key" not in payload["text"]
    assert "abc123" not in payload["text"]
    assert "AKIA" not in payload["text"]


def test_format_slack_payload_counts_each_category() -> None:
    diff = _diff(
        new_endpoints=["/a", "/b"],
        removed_endpoints=["/c"],
        new_subdomains=["x.example.com"],
    )
    payload = format_slack_payload(diff, "example.com")
    assert "+2 new endpoint(s)" in payload["text"]
    assert "-1 removed endpoint(s)" in payload["text"]
    assert "x.example.com" in payload["text"]
