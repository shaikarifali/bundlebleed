from __future__ import annotations

from bundlebleed.ai.prompt_loader import load_attack_chain_prompt, load_attack_chain_system_prompt
from bundlebleed.ai.providers.base import LLMProvider
from bundlebleed.ai.safety import flagged_unsafe_text
from bundlebleed.ai.schema import AttackChainBatch, AttackChainSuggestion
from bundlebleed.ai.validator import validate_chain_citations
from bundlebleed.hypotheses.models import Hypothesis


def _build_evidence_text(hypotheses: list[Hypothesis]) -> str:
    """The ONLY data that reaches the model — already-redacted hypothesis
    fields, one block per hypothesis. No secrets, no raw JS body, no cookie
    value ever appear here, since Hypothesis itself never carries them."""
    blocks: list[str] = []
    for hypothesis in hypotheses:
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
        blocks.append("\n".join(lines))
    return "\n\n".join(blocks)


def flagged_unsafe_next_steps(chains: list[AttackChainSuggestion]) -> list[str]:
    return flagged_unsafe_text([chain.suggested_next_step for chain in chains])


async def suggest_attack_chains(
    hypotheses: list[Hypothesis], provider: LLMProvider
) -> tuple[list[AttackChainSuggestion], list[str]]:
    """Suggest connections between >= 2 hypotheses from the same scan.
    Returns (chains, flagged_next_steps) — flagged_next_steps is non-empty
    only when a suggested next step reads like an exploitation/destructive
    instruction despite the system prompt forbidding it; the caller must
    surface that warning, never silently drop it.

    Every hypothesis_ids entry in every returned chain is guaranteed to be
    one of the input hypotheses' own ids — a hallucinated id is a hard
    failure (UncitedHypothesisError), never silently dropped (Invariant 4).
    """
    if len(hypotheses) < 2:
        return [], []

    system = load_attack_chain_system_prompt()
    user_template = load_attack_chain_prompt()
    evidence_text = _build_evidence_text(hypotheses)
    user_prompt = user_template.text.format(evidence=evidence_text)

    batch = await provider.complete_structured(system.text, user_prompt, AttackChainBatch)
    validate_chain_citations(batch, {h.id for h in hypotheses})

    return batch.chains, flagged_unsafe_next_steps(batch.chains)
