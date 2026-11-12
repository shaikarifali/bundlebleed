from __future__ import annotations

import json

import pytest

from bundlebleed.ai.schema import AttackChainSuggestion, ReportDraft
from bundlebleed.evidence.store import (
    load_hypothesis,
    record_verification_outcome,
    write_attack_chains,
    write_evidence_bundle,
    write_evidence_store,
    write_report_draft,
)
from bundlebleed.hypotheses.models import Hypothesis, HypothesisStatus


def _hypothesis(**overrides: object) -> Hypothesis:
    defaults: dict[str, object] = {
        "id": "abc123",
        "target_kind": "secret",
        "target_value": "AKIA****MNOP",
        "source_url": "https://example.com/app.js",
        "bug_classes": ["Hardcoded Credential Exposure"],
        "evidence_chain": ["Matched the aws_access_key pattern"],
        "confidence": 0.2,
        "risk": "critical",
        "proposed_test": "Verify liveness with KeyHacks.",
    }
    defaults.update(overrides)
    return Hypothesis(**defaults)  # type: ignore[arg-type]


def test_write_evidence_bundle_writes_finding_json(tmp_path) -> None:  # type: ignore[no-untyped-def]
    hypothesis = _hypothesis()
    path = write_evidence_bundle(hypothesis, tmp_path)

    assert path == tmp_path / "evidence" / "abc123" / "finding.json"
    assert path.exists()

    data = json.loads(path.read_text())
    assert data["id"] == "abc123"
    assert data["risk"] == "critical"


def test_write_evidence_bundle_never_contains_raw_secret_value(tmp_path) -> None:  # type: ignore[no-untyped-def]
    hypothesis = _hypothesis(target_value="AKIA****MNOP")
    path = write_evidence_bundle(hypothesis, tmp_path)

    raw = path.read_text()
    assert "AKIA****MNOP" in raw  # the redacted preview is fine
    assert "AKIAABCDEFGHIJKLMNOP" not in raw  # a real unredacted key must never appear


def test_write_evidence_store_writes_one_file_per_hypothesis(tmp_path) -> None:  # type: ignore[no-untyped-def]
    hypotheses = [_hypothesis(id="id-1"), _hypothesis(id="id-2")]
    paths = write_evidence_store(hypotheses, tmp_path)

    assert len(paths) == 2
    assert all(p.exists() for p in paths)
    assert {p.parent.name for p in paths} == {"id-1", "id-2"}


def test_record_verification_outcome_updates_status(tmp_path) -> None:  # type: ignore[no-untyped-def]
    hypothesis = _hypothesis()
    write_evidence_bundle(hypothesis, tmp_path)

    path = record_verification_outcome(tmp_path, "abc123", HypothesisStatus.CONFIRMED)

    data = json.loads(path.read_text())
    assert data["status"] == "confirmed"


def test_record_verification_outcome_appends_note_to_evidence_chain(tmp_path) -> None:  # type: ignore[no-untyped-def]
    hypothesis = _hypothesis()
    write_evidence_bundle(hypothesis, tmp_path)

    path = record_verification_outcome(
        tmp_path, "abc123", HypothesisStatus.REJECTED, note="Tested manually, properly protected."
    )

    data = json.loads(path.read_text())
    assert any("Tested manually" in entry for entry in data["evidence_chain"])
    assert data["status"] == "rejected"


def test_record_verification_outcome_raises_for_unknown_hypothesis(tmp_path) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(FileNotFoundError):
        record_verification_outcome(tmp_path, "does-not-exist", HypothesisStatus.CONFIRMED)


def test_record_verification_outcome_without_note_does_not_touch_evidence_chain(tmp_path) -> None:  # type: ignore[no-untyped-def]
    hypothesis = _hypothesis()
    write_evidence_bundle(hypothesis, tmp_path)

    path = record_verification_outcome(tmp_path, "abc123", HypothesisStatus.INCONCLUSIVE)

    data = json.loads(path.read_text())
    assert data["evidence_chain"] == hypothesis.evidence_chain


def test_load_hypothesis_round_trips(tmp_path) -> None:  # type: ignore[no-untyped-def]
    hypothesis = _hypothesis()
    write_evidence_bundle(hypothesis, tmp_path)

    loaded = load_hypothesis(tmp_path, "abc123")
    assert loaded == hypothesis


def test_load_hypothesis_raises_for_unknown_id(tmp_path) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(FileNotFoundError):
        load_hypothesis(tmp_path, "does-not-exist")


def _report_draft() -> ReportDraft:
    return ReportDraft(
        title="IDOR on user profile",
        summary="Untested hypothesis awaiting manual verification.",
        vulnerability_type="IDOR",
        steps_to_reproduce=["Compare responses across two accounts."],
        impact="Potential unauthorized data access.",
        suggested_fix="Add server-side ownership checks.",
    )


def test_write_report_draft_writes_markdown_file(tmp_path) -> None:  # type: ignore[no-untyped-def]
    path = write_report_draft(_report_draft(), tmp_path, "abc123")

    assert path == tmp_path / "evidence" / "abc123" / "report-draft.md"
    content = path.read_text()
    assert "IDOR on user profile" in content
    assert "Add server-side ownership checks." in content


def test_write_report_draft_carries_the_unverified_disclaimer(tmp_path) -> None:  # type: ignore[no-untyped-def]
    path = write_report_draft(_report_draft(), tmp_path, "abc123")
    content = path.read_text()
    assert "not verified" in content.lower()
    assert "not submitted" in content.lower()


def _chain() -> AttackChainSuggestion:
    return AttackChainSuggestion(
        title="Leaked token enables IDOR",
        hypothesis_ids=["hyp-1", "hyp-2"],
        narrative="The leaked token could authenticate the IDOR endpoint.",
        impact="Unauthorized access to other users' data.",
        suggested_next_step="Manually verify the token grants access.",
    )


def test_write_attack_chains_writes_markdown_at_output_root(tmp_path) -> None:  # type: ignore[no-untyped-def]
    path = write_attack_chains([_chain()], tmp_path)

    assert path == tmp_path / "attack-chains.md"
    content = path.read_text()
    assert "Leaked token enables IDOR" in content
    assert "hyp-1" in content
    assert "hyp-2" in content
    assert "Manually verify the token grants access." in content


def test_write_attack_chains_carries_the_unverified_disclaimer(tmp_path) -> None:  # type: ignore[no-untyped-def]
    path = write_attack_chains([_chain()], tmp_path)
    content = path.read_text().lower()
    assert "unverified" in content
    assert "human review required" in content


def test_write_attack_chains_handles_empty_list(tmp_path) -> None:  # type: ignore[no-untyped-def]
    path = write_attack_chains([], tmp_path)
    content = path.read_text()
    assert "No meaningful chains found" in content
