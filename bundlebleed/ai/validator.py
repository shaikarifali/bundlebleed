from __future__ import annotations

from bundlebleed.ai.schema import AttackChainBatch, EndpointIntelBatch


class UncitedEvidenceError(ValueError):
    """Raised when a model verdict cites an evidence_id that was never in
    the prompt — CLAUDE.md Invariant 4: every claim must cite an evidence ID
    present in the bundle; the validator rejects uncited claims. This is a
    hard failure (hallucination), never silently dropped or downgraded."""

    def __init__(self, evidence_id: str) -> None:
        super().__init__(f"model cited unknown evidence id: {evidence_id!r}")
        self.evidence_id = evidence_id


class UncitedHypothesisError(ValueError):
    """Raised when a suggested attack chain cites a hypothesis id that was
    never in the prompt — same Invariant 4 discipline as
    `UncitedEvidenceError`, applied to attack-chain suggestions."""

    def __init__(self, hypothesis_id: str) -> None:
        super().__init__(f"model cited unknown hypothesis id: {hypothesis_id!r}")
        self.hypothesis_id = hypothesis_id


def validate_citations(batch: EndpointIntelBatch, valid_evidence_ids: set[str]) -> None:
    for verdict in batch.verdicts:
        if verdict.evidence_id not in valid_evidence_ids:
            raise UncitedEvidenceError(verdict.evidence_id)


def validate_chain_citations(batch: AttackChainBatch, valid_hypothesis_ids: set[str]) -> None:
    for chain in batch.chains:
        for hypothesis_id in chain.hypothesis_ids:
            if hypothesis_id not in valid_hypothesis_ids:
                raise UncitedHypothesisError(hypothesis_id)
