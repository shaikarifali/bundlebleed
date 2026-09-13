from __future__ import annotations

from pydantic import BaseModel, Field


class RequestDraft(BaseModel):
    """A request that will NEVER be sent by this tool — only rendered as an
    artifact for a human to run themselves. `headers` never contains a real
    credential value, only a placeholder (see drafter.py)."""

    method: str = "GET"
    url: str
    headers: dict[str, str] = Field(default_factory=dict)
    comment: str = ""


class VerificationDraft(BaseModel):
    hypothesis_id: str
    baseline: RequestDraft
    test: RequestDraft
    notes: list[str] = Field(default_factory=list)
