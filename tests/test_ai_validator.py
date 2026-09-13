from __future__ import annotations

import pytest

from bundlebleed.ai.schema import (
    AttackChainBatch,
    AttackChainSuggestion,
    EndpointIntelBatch,
    EndpointVerdict,
)
from bundlebleed.ai.validator import (
    UncitedEvidenceError,
    UncitedHypothesisError,
    validate_chain_citations,
    validate_citations,
)


def _verdict(evidence_id: str) -> EndpointVerdict:
    return EndpointVerdict(
        evidence_id=evidence_id,
        bug_classes=["IDOR"],
        priority="high",
        test_plan="Compare responses for two different ids while authenticated as one user.",
        confidence=0.8,
    )


def test_validate_citations_accepts_known_ids() -> None:
    batch = EndpointIntelBatch(verdicts=[_verdict("abc123")])
    validate_citations(batch, {"abc123", "def456"})  # must not raise


def test_validate_citations_rejects_hallucinated_id() -> None:
    batch = EndpointIntelBatch(verdicts=[_verdict("not-a-real-id")])
    with pytest.raises(UncitedEvidenceError) as exc_info:
        validate_citations(batch, {"abc123"})
    assert exc_info.value.evidence_id == "not-a-real-id"


def test_validate_citations_checks_every_verdict_not_just_the_first() -> None:
    batch = EndpointIntelBatch(verdicts=[_verdict("abc123"), _verdict("bogus")])
    with pytest.raises(UncitedEvidenceError):
        validate_citations(batch, {"abc123"})


def _chain(*hypothesis_ids: str) -> AttackChainSuggestion:
    return AttackChainSuggestion(
        title="Combined access",
        hypothesis_ids=list(hypothesis_ids),
        narrative="Chaining the two findings together.",
        impact="Full account access.",
        suggested_next_step="Manually correlate the two findings.",
    )


def test_validate_chain_citations_accepts_known_ids() -> None:
    batch = AttackChainBatch(chains=[_chain("hyp-1", "hyp-2")])
    validate_chain_citations(batch, {"hyp-1", "hyp-2", "hyp-3"})  # must not raise


def test_validate_chain_citations_rejects_hallucinated_id() -> None:
    batch = AttackChainBatch(chains=[_chain("hyp-1", "not-a-real-id")])
    with pytest.raises(UncitedHypothesisError) as exc_info:
        validate_chain_citations(batch, {"hyp-1", "hyp-2"})
    assert exc_info.value.hypothesis_id == "not-a-real-id"


def test_validate_chain_citations_checks_every_chain_not_just_the_first() -> None:
    batch = AttackChainBatch(chains=[_chain("hyp-1", "hyp-2"), _chain("hyp-1", "bogus")])
    with pytest.raises(UncitedHypothesisError):
        validate_chain_citations(batch, {"hyp-1", "hyp-2"})
