from __future__ import annotations

import re
from urllib.parse import urljoin

from bundlebleed.collectors.orchestrator import active_scan_authorized
from bundlebleed.config import BundleBleedConfig
from bundlebleed.hypotheses.models import Hypothesis
from bundlebleed.scope.models import ScopeConfig
from bundlebleed.verification.models import RequestDraft, VerificationDraft

_DIGIT_RUN_RE = re.compile(r"\d+")


def _increment_last_numeric_segment(value: str) -> str | None:
    """Bump the rightmost run of digits by exactly one. Returns None if
    there's no digit run to bump — never guesses, never ranges."""
    matches = list(_DIGIT_RUN_RE.finditer(value))
    if not matches:
        return None
    last = matches[-1]
    incremented = str(int(last.group()) + 1)
    return value[: last.start()] + incremented + value[last.end() :]


def draft_verification(
    hypothesis: Hypothesis,
    config: BundleBleedConfig,
    scope_config: ScopeConfig,
    cli_active_flag: bool,
    session_role_hint: str | None = None,
) -> VerificationDraft | None:
    """Draft a single-variant IDOR verification request pair.

    Returns None (does nothing) unless active scanning is fully authorized
    (config flag + CLI flag + scope.yaml attestation — Invariant 3), the
    hypothesis is IDOR-shaped, and it has a concrete numeric id to bump by
    exactly one (never a range/sweep — Invariant 1 forbids path
    brute-forcing). This function only ever returns data; it never sends
    a request itself, and a Cookie header (if any) is always the
    `$BUNDLEBLEED_COOKIE` placeholder, never a real value.
    """
    if not active_scan_authorized(config, scope_config, cli_active_flag):
        return None
    if "IDOR" not in hypothesis.bug_classes:
        return None

    test_value = _increment_last_numeric_segment(hypothesis.target_value)
    if test_value is None:
        return None

    baseline_url = urljoin(hypothesis.source_url, hypothesis.target_value)
    test_url = urljoin(hypothesis.source_url, test_value)

    headers: dict[str, str] = {}
    notes = [
        "Baseline vs. test: identical request, only the object id differs by exactly one.",
        "This is a draft only — nothing here has been sent. Run it yourself and compare.",
    ]
    if session_role_hint:
        headers["Cookie"] = "$BUNDLEBLEED_COOKIE"
        notes.append(f"Set $BUNDLEBLEED_COOKIE to the '{session_role_hint}' session's cookie.")

    return VerificationDraft(
        hypothesis_id=hypothesis.id,
        baseline=RequestDraft(
            url=baseline_url, headers=dict(headers), comment="baseline (original id)"
        ),
        test=RequestDraft(url=test_url, headers=dict(headers), comment="test (id + 1)"),
        notes=notes,
    )
