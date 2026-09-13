from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class ScanDiff(BaseModel):
    previous_scan_run_id: str
    previous_started_at: datetime
    new_endpoints: list[str] = Field(default_factory=list)
    removed_endpoints: list[str] = Field(default_factory=list)
    new_secrets: list[str] = Field(default_factory=list)
    removed_secrets: list[str] = Field(default_factory=list)
    new_subdomains: list[str] = Field(default_factory=list)
    removed_subdomains: list[str] = Field(default_factory=list)
    # Endpoint values that were only reachable via an authenticated bundle
    # last scan, and are now visible from an unauthenticated one — a
    # broken-access-control regression, the flagship reason this exists.
    access_control_regressions: list[str] = Field(default_factory=list)
