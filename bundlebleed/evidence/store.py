from __future__ import annotations

from pathlib import Path

from bundlebleed.ai.schema import AttackChainSuggestion, ReportDraft
from bundlebleed.hypotheses.models import Hypothesis, HypothesisStatus


def write_evidence_bundle(hypothesis: Hypothesis, output_dir: Path) -> Path:
    """One JSON bundle per hypothesis: `<output_dir>/evidence/<id>/finding.json`.

    Only ever built from already-redacted model data (Hypothesis.target_value
    for a secret is the redacted preview, never the raw match). A verified
    request/response pair never lands here automatically — this tool never
    sends the drafted requests itself (see bundlebleed/verification/); only
    `record_verification_outcome` below, driven by an explicit human action,
    ever advances a hypothesis past `ready_to_test`/`awaiting_approval`.
    """
    bundle_dir = output_dir / "evidence" / hypothesis.id
    bundle_dir.mkdir(parents=True, exist_ok=True)
    path = bundle_dir / "finding.json"
    path.write_text(hypothesis.model_dump_json(indent=2) + "\n")
    return path


def write_evidence_store(hypotheses: list[Hypothesis], output_dir: Path) -> list[Path]:
    return [write_evidence_bundle(h, output_dir) for h in hypotheses]


def load_hypothesis(output_dir: Path, hypothesis_id: str) -> Hypothesis:
    finding_path = output_dir / "evidence" / hypothesis_id / "finding.json"
    if not finding_path.exists():
        raise FileNotFoundError(
            f"no evidence bundle for hypothesis {hypothesis_id!r} at {finding_path}"
        )
    return Hypothesis.model_validate_json(finding_path.read_text())


def record_verification_outcome(
    output_dir: Path, hypothesis_id: str, status: HypothesisStatus, note: str | None = None
) -> Path:
    """Record what a HUMAN found after manually running the drafted
    verification requests. This is the only way a hypothesis's status ever
    changes to CONFIRMED/REJECTED/INCONCLUSIVE — never automatic.
    """
    hypothesis = load_hypothesis(output_dir, hypothesis_id)
    updates: dict[str, object] = {"status": status}
    if note:
        updates["evidence_chain"] = [*hypothesis.evidence_chain, f"Human verification note: {note}"]
    hypothesis = hypothesis.model_copy(update=updates)

    finding_path = output_dir / "evidence" / hypothesis_id / "finding.json"
    finding_path.write_text(hypothesis.model_dump_json(indent=2) + "\n")
    return finding_path


def write_report_draft(draft: ReportDraft, output_dir: Path, hypothesis_id: str) -> Path:
    """Write report-draft.md into a hypothesis's evidence folder. Always
    labeled as an unverified AI draft — this tool never submits it
    anywhere and never treats it as confirming the hypothesis.
    """
    bundle_dir = output_dir / "evidence" / hypothesis_id
    bundle_dir.mkdir(parents=True, exist_ok=True)
    path = bundle_dir / "report-draft.md"

    steps = "\n".join(f"{i + 1}. {step}" for i, step in enumerate(draft.steps_to_reproduce))
    content = (
        f"# {draft.title}\n\n"
        "**AI-drafted report — not verified, not submitted. Review every "
        "claim before using it.**\n\n"
        f"## Summary\n{draft.summary}\n\n"
        f"## Vulnerability Type\n{draft.vulnerability_type}\n\n"
        f"## Steps to Reproduce\n{steps}\n\n"
        f"## Impact\n{draft.impact}\n\n"
        f"## Suggested Fix\n{draft.suggested_fix}\n"
    )
    path.write_text(content)
    return path


def write_attack_chains(chains: list[AttackChainSuggestion], output_dir: Path) -> Path:
    """Write attack-chains.md at the top of the scan's output directory
    (chains span multiple hypotheses, so — unlike a report draft — this
    doesn't belong under any single hypothesis's evidence folder). Always
    labeled as an AI suggestion — this tool never asserts a chain works,
    was tested, or that any hypothesis in it is more than what its own
    status says, and never acts on a suggestion itself.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "attack-chains.md"

    if not chains:
        path.write_text(
            "# Suggested Attack Chains\n\n"
            "**AI-suggested — unverified, human review required.**\n\n"
            "No meaningful chains found between the scan's hypotheses.\n"
        )
        return path

    sections = []
    for chain in chains:
        ids = ", ".join(f"`{hid}`" for hid in chain.hypothesis_ids)
        sections.append(
            f"## {chain.title}\n\n"
            f"**Hypotheses involved:** {ids}\n\n"
            f"{chain.narrative}\n\n"
            f"### Impact\n{chain.impact}\n\n"
            f"### Suggested Next Step\n{chain.suggested_next_step}\n"
        )

    content = (
        "# Suggested Attack Chains\n\n"
        "**AI-suggested — unverified, human review required. This tool "
        "never confirms a chain works and never acts on a suggestion "
        "itself.**\n\n" + "\n".join(sections)
    )
    path.write_text(content)
    return path
