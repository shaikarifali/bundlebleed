from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class HypothesisStatus(StrEnum):
    """Full lifecycle per the plan. This stage only ever emits
    READY_TO_TEST — the states past it belong to the (not-yet-built)
    verification engine, which is the only thing allowed to move a
    hypothesis further."""

    DISCOVERED = "discovered"
    HYPOTHESIS = "hypothesis"
    READY_TO_TEST = "ready_to_test"
    AWAITING_APPROVAL = "awaiting_approval"
    TESTED = "tested"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    INCONCLUSIVE = "inconclusive"


class Hypothesis(BaseModel):
    id: str
    target_kind: str  # "endpoint" | "secret" | "subdomain" | "dom_finding"
    target_value: str
    source_url: str
    bug_classes: list[str] = Field(default_factory=list)
    evidence_chain: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)
    risk: str
    status: HypothesisStatus = HypothesisStatus.READY_TO_TEST
    proposed_test: str
