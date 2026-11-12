from __future__ import annotations

import re
from pathlib import Path

from bundlebleed.models import ScanResult

_UNSAFE_CHARS_RE = re.compile(r"[^A-Za-z0-9_.-]+")


def _safe_target_dirname(target: str) -> str:
    return _UNSAFE_CHARS_RE.sub("_", target)


def _target_dir(history_dir: Path, target: str) -> Path:
    return history_dir / _safe_target_dirname(target)


def save_snapshot(result: ScanResult, history_dir: Path, target: str) -> Path:
    """Persist a normalized snapshot of this scan under
    <history_dir>/<target>/<timestamp>-<scan_run_id>.json, for future diffing."""
    normalized = result.normalized()
    target_dir = _target_dir(history_dir, target)
    target_dir.mkdir(parents=True, exist_ok=True)
    timestamp = normalized.started_at.strftime("%Y%m%dT%H%M%SZ")
    path = target_dir / f"{timestamp}-{normalized.scan_run_id}.json"
    path.write_text(normalized.model_dump_json(indent=2) + "\n")
    return path


def load_latest_snapshot(history_dir: Path, target: str) -> ScanResult | None:
    """Load the most recent prior snapshot for `target`, or None if this is
    the first scan (never an error — absence of history is expected)."""
    target_dir = _target_dir(history_dir, target)
    if not target_dir.exists():
        return None
    snapshot_files = sorted(target_dir.glob("*.json"))
    if not snapshot_files:
        return None
    return ScanResult.model_validate_json(snapshot_files[-1].read_text())
