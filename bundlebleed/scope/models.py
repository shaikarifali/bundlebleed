from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class MatchType(StrEnum):
    EXACT = "exact"
    WILDCARD = "wildcard"


class ScopeEntry(BaseModel):
    domain: str
    match_type: MatchType = MatchType.EXACT


class ScanSettings(BaseModel):
    # None = no extra pacing beyond the downloader's own concurrency cap.
    requests_per_second: float | None = None
    delay_between_domains: float = 0.0


class ScopeConfig(BaseModel):
    in_scope: list[ScopeEntry] = Field(default_factory=list)
    out_of_scope: list[str] = Field(default_factory=list)
    excluded_paths: list[str] = Field(default_factory=list)
    # Active scanning (Invariant 3) requires this to be explicitly attested in
    # scope.yaml, on top of the --active CLI flag and the config's
    # active_scan_enabled setting. scope.txt / -t targets can never set this.
    authorization_attested: bool = False
    scan: ScanSettings = Field(default_factory=ScanSettings)


class Decision(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"


class ScopeDecision(BaseModel):
    url: str
    decision: Decision
    reason: str
