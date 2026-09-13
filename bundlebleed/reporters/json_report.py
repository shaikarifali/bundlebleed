from __future__ import annotations

from pathlib import Path

from bundlebleed.models import ScanResult


def write_json_report(result: ScanResult, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "scan-result.json"
    path.write_text(result.normalized().model_dump_json(indent=2) + "\n")
    return path
