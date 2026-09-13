from __future__ import annotations

from bundlebleed.ai.prompt_loader import load_report_writer_prompt, load_report_writer_system_prompt
from bundlebleed.ai.providers.base import LLMProvider
from bundlebleed.ai.safety import flagged_unsafe_text
from bundlebleed.ai.schema import ReportDraft
from bundlebleed.hypotheses.models import Hypothesis


def _build_evidence_text(hypothesis: Hypothesis) -> str:
    """The ONLY data that reaches the model — already-redacted hypothesis
    fields. No secrets, no raw JS body, no cookie value ever appear here,
    since Hypothesis itself never carries them."""
    lines = [
        f'<hypothesis id="{hypothesis.id}">',
        f"<bug_classes>{', '.join(hypothesis.bug_classes)}</bug_classes>",
        f"<target_kind>{hypothesis.target_kind}</target_kind>",
        f"<target_value>{hypothesis.target_value}</target_value>",
        f"<risk>{hypothesis.risk}</risk>",
        f"<confidence>{hypothesis.confidence:.2f}</confidence>",
        f"<status>{hypothesis.status.value}</status>",
        "<evidence_chain>",
    ]
    lines += [f"  <item>{item}</item>" for item in hypothesis.evidence_chain]
    lines.append("</evidence_chain>")
    lines.append(f"<proposed_test>{hypothesis.proposed_test}</proposed_test>")
    lines.append("</hypothesis>")
    return "\n".join(lines)


def flagged_unsafe_steps(draft: ReportDraft) -> list[str]:
    return flagged_unsafe_text(draft.steps_to_reproduce)


async def draft_report(
    hypothesis: Hypothesis, provider: LLMProvider
) -> tuple[ReportDraft, list[str]]:
    """Draft a bug bounty report from a hypothesis's own (already redacted)
    data. Returns (draft, flagged_steps) — flagged_steps is non-empty only
    when a step reads like an exploitation/destructive instruction despite
    the system prompt forbidding it; the caller must surface that warning,
    never silently drop it.
    """
    system = load_report_writer_system_prompt()
    user_template = load_report_writer_prompt()
    evidence_text = _build_evidence_text(hypothesis)
    user_prompt = user_template.text.format(evidence=evidence_text)

    draft = await provider.complete_structured(system.text, user_prompt, ReportDraft)
    return draft, flagged_unsafe_steps(draft)
