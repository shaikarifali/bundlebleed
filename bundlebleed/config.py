from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel


class BundleBleedConfig(BaseModel):
    output_dir: Path = Path("./results")
    report_formats: list[str] = ["json", "markdown"]

    # Invariant 3: active scanning needs this AND a CLI --active flag AND a
    # valid authorization_attested=True in the loaded scope.yaml. All three
    # must hold before any active collector (e.g. katana) is invoked. This
    # field lives in a separate app-level config file, deliberately not in
    # scope.yaml, so one file can't flip both the app policy and the
    # per-engagement attestation at once.
    active_scan_enabled: bool = False


def load_app_config(path: Path | None) -> BundleBleedConfig:
    if path is None or not path.exists():
        return BundleBleedConfig()
    raw = yaml.safe_load(path.read_text()) or {}
    if not isinstance(raw, dict):
        raise ValueError(f"{path}: expected a YAML mapping at the top level")
    return BundleBleedConfig.model_validate(raw)
