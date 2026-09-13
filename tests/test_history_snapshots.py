from __future__ import annotations

import time
from datetime import datetime

from bundlebleed.history.snapshots import load_latest_snapshot, save_snapshot
from bundlebleed.models import Endpoint, ScanResult


def _result(scan_run_id: str, endpoint_value: str) -> ScanResult:
    return ScanResult(
        scan_run_id=scan_run_id,
        started_at=datetime.now(),
        targets=["example.com"],
        endpoints=[
            Endpoint(value=endpoint_value, pattern_name="rest_api_path", source_url="https://e.com")
        ],
    )


def test_load_latest_snapshot_returns_none_when_no_history(tmp_path) -> None:  # type: ignore[no-untyped-def]
    assert load_latest_snapshot(tmp_path, "example.com") is None


def test_save_and_load_snapshot_round_trips(tmp_path) -> None:  # type: ignore[no-untyped-def]
    result = _result("run-1", "/api/v1/a")
    save_snapshot(result, tmp_path, "example.com")

    loaded = load_latest_snapshot(tmp_path, "example.com")
    assert loaded is not None
    assert loaded.scan_run_id == "run-1"
    assert loaded.endpoints[0].value == "/api/v1/a"


def test_load_latest_snapshot_picks_the_most_recent_one(tmp_path) -> None:  # type: ignore[no-untyped-def]
    save_snapshot(_result("run-1", "/api/v1/old"), tmp_path, "example.com")
    time.sleep(1.1)  # ensure a distinct filesystem-sortable timestamp
    save_snapshot(_result("run-2", "/api/v1/new"), tmp_path, "example.com")

    loaded = load_latest_snapshot(tmp_path, "example.com")
    assert loaded is not None
    assert loaded.scan_run_id == "run-2"


def test_snapshots_for_different_targets_do_not_collide(tmp_path) -> None:  # type: ignore[no-untyped-def]
    save_snapshot(_result("run-a", "/api/a"), tmp_path, "example.com")
    save_snapshot(_result("run-b", "/api/b"), tmp_path, "other.com")

    a = load_latest_snapshot(tmp_path, "example.com")
    b = load_latest_snapshot(tmp_path, "other.com")
    assert a is not None and a.scan_run_id == "run-a"
    assert b is not None and b.scan_run_id == "run-b"


def test_target_dirname_is_filesystem_safe(tmp_path) -> None:  # type: ignore[no-untyped-def]
    result = _result("run-1", "/api/a")
    path = save_snapshot(result, tmp_path, "example.com,api.example.com")
    assert path.exists()
    # no raw commas/slashes introducing unexpected nested directories
    assert path.parent.parent == tmp_path
