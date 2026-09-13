from __future__ import annotations

from dataclasses import dataclass

# Weights follow the plan's multi-factor confidence table, restricted to
# factors this stage can actually compute. Differential evidence still
# needs a stage that doesn't exist yet (the tool actually sending a
# verification request, which it deliberately never does) — it is absent
# from scoring, not faked as zero.
_STATIC_PATTERN_WEIGHT = 0.2
_JS_BODY_ONLY_WEIGHT = 0.15
_RULE_MATCH_WEIGHT = 0.2
_AUTH_CONTEXT_WEIGHT = 0.2  # found only in an authenticated-session bundle
_HISTORICAL_MATCH_WEIGHT = 0.1  # also present in a prior scan of the same target
_RUNTIME_EVIDENCE_WEIGHT = 0.3  # the running page actually called this endpoint
_AI_CONFIDENCE_CAP = 0.1  # Invariant 4: AI confidence alone never confirms a finding


@dataclass(frozen=True)
class ConfidenceFactors:
    static_pattern_match: bool = False
    js_body_only: bool = False
    rule_pattern_match: bool = False
    auth_context: bool = False
    historical_match: bool = False
    runtime_evidence: bool = False
    ai_confidence: float | None = None


def score_confidence(factors: ConfidenceFactors) -> float:
    score = 0.0
    if factors.static_pattern_match:
        score += _STATIC_PATTERN_WEIGHT
    if factors.js_body_only:
        score += _JS_BODY_ONLY_WEIGHT
    if factors.rule_pattern_match:
        score += _RULE_MATCH_WEIGHT
    if factors.auth_context:
        score += _AUTH_CONTEXT_WEIGHT
    if factors.historical_match:
        score += _HISTORICAL_MATCH_WEIGHT
    if factors.runtime_evidence:
        score += _RUNTIME_EVIDENCE_WEIGHT
    if factors.ai_confidence is not None:
        score += max(0.0, min(factors.ai_confidence, 1.0)) * _AI_CONFIDENCE_CAP
    return min(score, 1.0)


def risk_for_confidence(confidence: float) -> str:
    if confidence >= 0.6:
        return "high"
    if confidence >= 0.35:
        return "medium"
    return "low"
