from __future__ import annotations

from dataclasses import dataclass, field

from bundlebleed.ai.evidence import build_evidence_items, flagged_values, render_evidence_bundle
from bundlebleed.ai.prompt_loader import load_endpoint_analysis_prompt, load_system_prompt
from bundlebleed.ai.providers.base import LLMProvider
from bundlebleed.ai.schema import EndpointIntelBatch
from bundlebleed.ai.validator import validate_citations
from bundlebleed.models import AIEndpointVerdict, Endpoint


@dataclass
class EndpointIntelResult:
    verdicts: list[AIEndpointVerdict] = field(default_factory=list)
    injection_flags: list[str] = field(default_factory=list)


def _batched(items: list[Endpoint], size: int) -> list[list[Endpoint]]:
    return [items[i : i + size] for i in range(0, len(items), size)]


async def classify_endpoints(
    endpoints: list[Endpoint], provider: LLMProvider, batch_size: int = 20
) -> EndpointIntelResult:
    """Classify endpoints in batches. Never sends anything beyond
    pattern_name/value/source_url (no secrets, no raw JS body) — see
    `build_evidence_items`. Every returned verdict has already passed
    citation validation (Invariant 4): a hallucinated evidence_id raises
    rather than being silently included.
    """
    if not endpoints:
        return EndpointIntelResult()

    system = load_system_prompt()
    user_template = load_endpoint_analysis_prompt()

    result = EndpointIntelResult()

    for batch in _batched(endpoints, batch_size):
        items = build_evidence_items(batch)
        result.injection_flags.extend(flagged_values(items))

        by_id = {item.evidence_id: item for item in items}
        evidence_bundle = render_evidence_bundle(items)
        user_prompt = user_template.text.format(evidence_bundle=evidence_bundle)

        parsed = await provider.complete_structured(system.text, user_prompt, EndpointIntelBatch)
        validate_citations(parsed, set(by_id))

        for verdict in parsed.verdicts:
            item = by_id[verdict.evidence_id]
            result.verdicts.append(
                AIEndpointVerdict(
                    evidence_id=verdict.evidence_id,
                    endpoint_value=item.endpoint.value,
                    source_url=item.endpoint.source_url,
                    bug_classes=verdict.bug_classes,
                    priority=verdict.priority,
                    test_plan=verdict.test_plan,
                    confidence=verdict.confidence,
                    prompt_version=system.version,
                    model=provider.model,
                )
            )

    return result
