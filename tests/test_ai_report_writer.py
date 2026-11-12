from __future__ import annotations

import asyncio
from typing import TypeVar

from pydantic import BaseModel

from bundlebleed.ai.providers.base import LLMProvider
from bundlebleed.ai.schema import ReportDraft
from bundlebleed.ai.tasks.report_writer import (
    _build_evidence_text,
    draft_report,
    flagged_unsafe_steps,
)
from bundlebleed.hypotheses.models import Hypothesis

T = TypeVar("T", bound=BaseModel)


def _hypothesis(**overrides: object) -> Hypothesis:
    defaults: dict[str, object] = {
        "id": "hyp-1",
        "target_kind": "endpoint",
        "target_value": "/api/v1/users/123",
        "source_url": "https://example.com/app.js",
        "bug_classes": ["IDOR"],
        "evidence_chain": ["Endpoint discovered via pattern 'rest_api_path'"],
        "confidence": 0.5,
        "risk": "medium",
        "proposed_test": "Compare responses across two low-privilege accounts.",
    }
    defaults.update(overrides)
    return Hypothesis(**defaults)  # type: ignore[arg-type]


def _draft(**overrides: object) -> ReportDraft:
    defaults: dict[str, object] = {
        "title": "IDOR on user profile endpoint",
        "summary": "An untested hypothesis awaiting manual verification.",
        "vulnerability_type": "IDOR",
        "steps_to_reproduce": ["Compare responses across two low-privilege accounts."],
        "impact": "Potential unauthorized access to other users' data.",
        "suggested_fix": "Add server-side ownership checks.",
    }
    defaults.update(overrides)
    return ReportDraft(**defaults)  # type: ignore[arg-type]


class FakeProvider(LLMProvider):
    def __init__(self, response: ReportDraft) -> None:
        super().__init__(model="fake-model-1")
        self.calls: list[tuple[str, str]] = []
        self._response = response

    async def complete_structured(self, system: str, user: str, output_schema: type[T]) -> T:
        self.calls.append((system, user))
        return self._response  # type: ignore[return-value]


def test_build_evidence_text_includes_all_hypothesis_fields() -> None:
    hypothesis = _hypothesis()
    text = _build_evidence_text(hypothesis)

    assert "hyp-1" in text
    assert "IDOR" in text
    assert "/api/v1/users/123" in text
    assert "medium" in text
    assert "ready_to_test" in text
    assert "Compare responses across two low-privilege accounts." in text


def test_build_evidence_text_never_contains_secret_material() -> None:
    secret_hypothesis = _hypothesis(
        target_kind="secret",
        target_value="AKIA****MNOP",
        bug_classes=["Hardcoded Credential Exposure"],
    )
    text = _build_evidence_text(secret_hypothesis)
    assert "AKIA****MNOP" in text  # redacted preview is fine
    assert "AKIAABCDEFGHIJKLMNOP" not in text  # a real key must never appear


def test_flagged_unsafe_steps_detects_prohibited_language() -> None:
    draft = _draft(steps_to_reproduce=["Brute force the login form to confirm."])
    assert flagged_unsafe_steps(draft) == ["Brute force the login form to confirm."]


def test_flagged_unsafe_steps_empty_for_safe_steps() -> None:
    draft = _draft(steps_to_reproduce=["Compare responses across two low-privilege accounts."])
    assert flagged_unsafe_steps(draft) == []


def test_draft_report_returns_draft_and_no_flags_for_safe_output() -> None:
    hypothesis = _hypothesis()
    provider = FakeProvider(_draft())

    draft, flagged = asyncio.run(draft_report(hypothesis, provider))

    assert draft.title == "IDOR on user profile endpoint"
    assert flagged == []
    assert len(provider.calls) == 1


def test_draft_report_surfaces_flagged_steps_without_dropping_them() -> None:
    hypothesis = _hypothesis()
    unsafe_draft = _draft(steps_to_reproduce=["Try default password admin:admin."])
    provider = FakeProvider(unsafe_draft)

    draft, flagged = asyncio.run(draft_report(hypothesis, provider))

    assert draft.steps_to_reproduce == ["Try default password admin:admin."]
    assert flagged == ["Try default password admin:admin."]


def test_draft_report_prompt_never_contains_secret_material() -> None:
    hypothesis = _hypothesis(
        target_kind="secret",
        target_value="AKIA****MNOP",
        bug_classes=["Hardcoded Credential Exposure"],
    )
    provider = FakeProvider(_draft())

    asyncio.run(draft_report(hypothesis, provider))

    system, user = provider.calls[0]
    assert "AKIAABCDEFGHIJKLMNOP" not in system
    assert "AKIAABCDEFGHIJKLMNOP" not in user
