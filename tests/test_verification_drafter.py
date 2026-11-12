from __future__ import annotations

from bundlebleed.config import BundleBleedConfig
from bundlebleed.hypotheses.models import Hypothesis
from bundlebleed.scope.models import ScopeConfig
from bundlebleed.verification.drafter import draft_verification


def _idor_hypothesis(target_value: str = "/api/v1/users/123") -> Hypothesis:
    return Hypothesis(
        id="hyp-1",
        target_kind="endpoint",
        target_value=target_value,
        source_url="https://example.com/app.js",
        bug_classes=["IDOR"],
        evidence_chain=["test"],
        confidence=0.5,
        risk="medium",
        proposed_test="test",
    )


def _authorized_config_and_scope() -> tuple[BundleBleedConfig, ScopeConfig]:
    return BundleBleedConfig(active_scan_enabled=True), ScopeConfig(authorization_attested=True)


def test_draft_verification_requires_full_authorization() -> None:
    hyp = _idor_hypothesis()

    # missing config flag
    unauthorized_config = BundleBleedConfig(active_scan_enabled=False)
    scope_config = ScopeConfig(authorization_attested=True)
    assert draft_verification(hyp, unauthorized_config, scope_config, True) is None

    # missing scope.yaml attestation
    config = BundleBleedConfig(active_scan_enabled=True)
    unattested_scope = ScopeConfig(authorization_attested=False)
    assert draft_verification(hyp, config, unattested_scope, True) is None

    # missing CLI flag
    config2, scope2 = _authorized_config_and_scope()
    assert draft_verification(hyp, config2, scope2, False) is None


def test_draft_verification_generates_exactly_one_test_url_id_plus_one() -> None:
    hyp = _idor_hypothesis("/api/v1/users/123")
    config, scope_config = _authorized_config_and_scope()

    draft = draft_verification(hyp, config, scope_config, True)

    assert draft is not None
    assert draft.baseline.url == "https://example.com/api/v1/users/123"
    assert draft.test.url == "https://example.com/api/v1/users/124"


def test_draft_verification_returns_none_for_non_idor_hypothesis() -> None:
    hyp = _idor_hypothesis()
    hyp = hyp.model_copy(update={"bug_classes": ["Broken Function-Level Authorization"]})
    config, scope_config = _authorized_config_and_scope()
    assert draft_verification(hyp, config, scope_config, True) is None


def test_draft_verification_returns_none_without_a_numeric_id() -> None:
    hyp = _idor_hypothesis("/dashboard/:userId")
    config, scope_config = _authorized_config_and_scope()
    assert draft_verification(hyp, config, scope_config, True) is None


def test_draft_verification_never_embeds_a_real_cookie_value() -> None:
    hyp = _idor_hypothesis()
    config, scope_config = _authorized_config_and_scope()

    draft = draft_verification(hyp, config, scope_config, True, session_role_hint="admin")

    assert draft is not None
    assert draft.baseline.headers["Cookie"] == "$BUNDLEBLEED_COOKIE"
    assert draft.test.headers["Cookie"] == "$BUNDLEBLEED_COOKIE"
    assert any("admin" in note for note in draft.notes)


def test_draft_verification_no_cookie_header_without_session_hint() -> None:
    hyp = _idor_hypothesis()
    config, scope_config = _authorized_config_and_scope()

    draft = draft_verification(hyp, config, scope_config, True)

    assert draft is not None
    assert "Cookie" not in draft.baseline.headers
    assert "Cookie" not in draft.test.headers
