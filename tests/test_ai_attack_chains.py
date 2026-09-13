from __future__ import annotations

import asyncio
from typing import TypeVar

import pytest
from pydantic import BaseModel

from bundlebleed.ai.providers.base import LLMProvider
from bundlebleed.ai.schema import AttackChainBatch, AttackChainSuggestion
from bundlebleed.ai.tasks.attack_chains import (
    _build_evidence_text,
    flagged_unsafe_next_steps,
    suggest_attack_chains,
)
from bundlebleed.ai.validator import UncitedHypothesisError
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


def _chain(**overrides: object) -> AttackChainSuggestion:
    defaults: dict[str, object] = {
        "title": "Leaked token enables IDOR",
        "hypothesis_ids": ["hyp-1", "hyp-2"],
        "narrative": "The leaked token from hyp-2 could authenticate the IDOR in hyp-1.",
        "impact": "Unauthorized access to other users' data.",
        "suggested_next_step": "Manually verify the token grants access to the endpoint.",
    }
    defaults.update(overrides)
    return AttackChainSuggestion(**defaults)  # type: ignore[arg-type]


class FakeProvider(LLMProvider):
    def __init__(self, response: AttackChainBatch) -> None:
        super().__init__(model="fake-model-1")
        self.calls: list[tuple[str, str]] = []
        self._response = response

    async def complete_structured(self, system: str, user: str, output_schema: type[T]) -> T:
        self.calls.append((system, user))
        return self._response  # type: ignore[return-value]


def test_build_evidence_text_includes_every_hypothesis() -> None:
    hyp1 = _hypothesis(id="hyp-1")
    hyp2 = _hypothesis(id="hyp-2", target_value="/api/v1/users/456")
    text = _build_evidence_text([hyp1, hyp2])

    assert "hyp-1" in text
    assert "hyp-2" in text
    assert "/api/v1/users/123" in text
    assert "/api/v1/users/456" in text


def test_build_evidence_text_never_contains_secret_material() -> None:
    secret_hypothesis = _hypothesis(
        id="hyp-secret",
        target_kind="secret",
        target_value="AKIA****MNOP",
        bug_classes=["Hardcoded Credential Exposure"],
    )
    text = _build_evidence_text([secret_hypothesis, _hypothesis(id="hyp-1")])
    assert "AKIA****MNOP" in text
    assert "AKIAABCDEFGHIJKLMNOP" not in text


def test_flagged_unsafe_next_steps_detects_prohibited_language() -> None:
    chains = [_chain(suggested_next_step="Brute force the login form to confirm.")]
    assert flagged_unsafe_next_steps(chains) == ["Brute force the login form to confirm."]


def test_flagged_unsafe_next_steps_empty_for_safe_steps() -> None:
    chains = [_chain()]
    assert flagged_unsafe_next_steps(chains) == []


def test_suggest_attack_chains_returns_chains_and_no_flags() -> None:
    hyp1, hyp2 = _hypothesis(id="hyp-1"), _hypothesis(id="hyp-2")
    provider = FakeProvider(AttackChainBatch(chains=[_chain()]))

    chains, flagged = asyncio.run(suggest_attack_chains([hyp1, hyp2], provider))

    assert len(chains) == 1
    assert flagged == []
    assert len(provider.calls) == 1


def test_suggest_attack_chains_returns_empty_with_fewer_than_two_hypotheses() -> None:
    provider = FakeProvider(AttackChainBatch(chains=[_chain()]))
    chains, flagged = asyncio.run(suggest_attack_chains([_hypothesis(id="hyp-1")], provider))

    assert chains == []
    assert flagged == []
    assert provider.calls == []  # never even calls the model for a single hypothesis


def test_suggest_attack_chains_raises_on_hallucinated_hypothesis_id() -> None:
    hyp1, hyp2 = _hypothesis(id="hyp-1"), _hypothesis(id="hyp-2")
    bad_chain = _chain(hypothesis_ids=["hyp-1", "not-a-real-id"])
    provider = FakeProvider(AttackChainBatch(chains=[bad_chain]))

    with pytest.raises(UncitedHypothesisError):
        asyncio.run(suggest_attack_chains([hyp1, hyp2], provider))


def test_suggest_attack_chains_surfaces_flagged_steps_without_dropping_them() -> None:
    hyp1, hyp2 = _hypothesis(id="hyp-1"), _hypothesis(id="hyp-2")
    unsafe_chain = _chain(suggested_next_step="Try default password admin:admin.")
    provider = FakeProvider(AttackChainBatch(chains=[unsafe_chain]))

    chains, flagged = asyncio.run(suggest_attack_chains([hyp1, hyp2], provider))

    assert chains[0].suggested_next_step == "Try default password admin:admin."
    assert flagged == ["Try default password admin:admin."]


def test_suggest_attack_chains_prompt_never_contains_secret_material() -> None:
    secret_hypothesis = _hypothesis(
        id="hyp-secret",
        target_kind="secret",
        target_value="AKIA****MNOP",
        bug_classes=["Hardcoded Credential Exposure"],
    )
    provider = FakeProvider(AttackChainBatch(chains=[]))

    asyncio.run(suggest_attack_chains([secret_hypothesis, _hypothesis(id="hyp-1")], provider))

    system, user = provider.calls[0]
    assert "AKIAABCDEFGHIJKLMNOP" not in system
    assert "AKIAABCDEFGHIJKLMNOP" not in user
