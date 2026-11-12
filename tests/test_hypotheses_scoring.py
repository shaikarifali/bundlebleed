from __future__ import annotations

from bundlebleed.hypotheses.scoring import ConfidenceFactors, risk_for_confidence, score_confidence


def test_no_factors_scores_zero() -> None:
    assert score_confidence(ConfidenceFactors()) == 0.0


def test_static_pattern_match_alone() -> None:
    assert score_confidence(ConfidenceFactors(static_pattern_match=True)) == 0.2


def test_all_static_factors_combine_additively() -> None:
    score = score_confidence(
        ConfidenceFactors(static_pattern_match=True, js_body_only=True, rule_pattern_match=True)
    )
    assert round(score, 2) == 0.55  # 0.2 + 0.15 + 0.2


def test_ai_confidence_contribution_is_capped_low() -> None:
    """Invariant 4: AI confidence alone must never be enough to confirm."""
    score = score_confidence(ConfidenceFactors(ai_confidence=1.0))
    assert score <= 0.1


def test_ai_confidence_is_clamped_to_valid_range() -> None:
    over = score_confidence(ConfidenceFactors(ai_confidence=5.0))
    under = score_confidence(ConfidenceFactors(ai_confidence=-5.0))
    assert over == score_confidence(ConfidenceFactors(ai_confidence=1.0))
    assert under == 0.0


def test_score_never_exceeds_one() -> None:
    score = score_confidence(
        ConfidenceFactors(
            static_pattern_match=True,
            js_body_only=True,
            rule_pattern_match=True,
            auth_context=True,
            historical_match=True,
            ai_confidence=1.0,
        )
    )
    assert score <= 1.0


def test_historical_match_alone() -> None:
    assert score_confidence(ConfidenceFactors(historical_match=True)) == 0.1


def test_historical_match_combines_with_other_factors() -> None:
    without = score_confidence(ConfidenceFactors(static_pattern_match=True))
    with_history = score_confidence(
        ConfidenceFactors(static_pattern_match=True, historical_match=True)
    )
    assert with_history > without
    assert round(with_history - without, 2) == 0.1


def test_auth_context_alone() -> None:
    assert score_confidence(ConfidenceFactors(auth_context=True)) == 0.2


def test_auth_context_combines_with_other_factors() -> None:
    without = score_confidence(ConfidenceFactors(static_pattern_match=True))
    with_auth = score_confidence(ConfidenceFactors(static_pattern_match=True, auth_context=True))
    assert with_auth > without
    assert round(with_auth - without, 2) == 0.2


def test_risk_bands() -> None:
    assert risk_for_confidence(0.9) == "high"
    assert risk_for_confidence(0.6) == "high"
    assert risk_for_confidence(0.5) == "medium"
    assert risk_for_confidence(0.35) == "medium"
    assert risk_for_confidence(0.1) == "low"
