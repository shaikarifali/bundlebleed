from __future__ import annotations

from pydantic import BaseModel, Field


class EndpointVerdict(BaseModel):
    """The shape handed to the model as `output_format` for one endpoint's
    classification. `evidence_id` must be validated against the known
    evidence set by the caller — the schema alone cannot enforce that a
    given id was actually present in the prompt."""

    evidence_id: str
    bug_classes: list[str] = Field(default_factory=list)
    priority: str
    test_plan: str
    confidence: float = Field(ge=0.0, le=1.0)


class EndpointIntelBatch(BaseModel):
    verdicts: list[EndpointVerdict] = Field(default_factory=list)


class ReportDraft(BaseModel):
    """A draft only — never submitted anywhere by this tool, never treated
    as confirming a hypothesis. A human reviews and edits before use."""

    title: str
    summary: str
    vulnerability_type: str
    steps_to_reproduce: list[str] = Field(default_factory=list)
    impact: str
    suggested_fix: str


class AttackChainSuggestion(BaseModel):
    """A suggested connection between >= 2 existing hypotheses — pure
    analysis, never a claim that the chain works or was tested. Every id in
    `hypothesis_ids` must be validated by the caller against the hypothesis
    set actually given to the model; the schema alone cannot enforce that."""

    title: str
    hypothesis_ids: list[str] = Field(min_length=2)
    narrative: str
    impact: str
    suggested_next_step: str


class AttackChainBatch(BaseModel):
    chains: list[AttackChainSuggestion] = Field(default_factory=list)
