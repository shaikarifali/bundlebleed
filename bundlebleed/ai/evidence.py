from __future__ import annotations

import re
from dataclasses import dataclass

from bundlebleed.identity import endpoint_id
from bundlebleed.models import Endpoint

# Heuristic only — this never blocks or alters what gets sent (evidence is
# data, never instruction, per CLAUDE.md Invariant 5). It exists so a
# suspicious item is visibly flagged in the prompt and in the report,
# turning an injection attempt into a reported finding instead of a command
# the model might quietly obey.
_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+|any\s+)?(previous|prior|above)\s+instructions", re.I),
    re.compile(r"\byou are now\b", re.I),
    re.compile(r"\bsystem prompt\b", re.I),
    re.compile(r"\bnew instructions?\b", re.I),
    re.compile(r"disregard\s+(all\s+|any\s+)?(previous|prior)", re.I),
]


def looks_like_injection(text: str) -> bool:
    return any(pattern.search(text) for pattern in _INJECTION_PATTERNS)


def evidence_id_for(endpoint: Endpoint) -> str:
    """Deterministic id so the same endpoint gets the same id across runs —
    and the same id a Hypothesis generated from this endpoint would get,
    so AI verdicts and hypotheses can cross-reference each other."""
    return endpoint_id(endpoint)


@dataclass(frozen=True)
class EvidenceItem:
    evidence_id: str
    endpoint: Endpoint
    injection_suspected: bool


def build_evidence_items(endpoints: list[Endpoint]) -> list[EvidenceItem]:
    """Build the ONLY data that ever reaches the model for endpoint
    classification: pattern_name/value/source_url. No secrets, no raw JS
    body content, no severity values — those never enter an AI prompt."""
    items = []
    for endpoint in endpoints:
        suspected = looks_like_injection(endpoint.value) or looks_like_injection(
            endpoint.source_url
        )
        items.append(
            EvidenceItem(
                evidence_id=evidence_id_for(endpoint),
                endpoint=endpoint,
                injection_suspected=suspected,
            )
        )
    return items


def render_evidence_bundle(items: list[EvidenceItem]) -> str:
    """Render evidence as clearly delimited, inert data for the prompt."""
    lines = ["<evidence>"]
    for item in items:
        flag = ' flagged="possible-injection-attempt"' if item.injection_suspected else ""
        lines.append(
            f'<item id="{item.evidence_id}" pattern="{item.endpoint.pattern_name}"{flag}>'
            f"{item.endpoint.value}</item>"
        )
    lines.append("</evidence>")
    return "\n".join(lines)


def flagged_values(items: list[EvidenceItem]) -> list[str]:
    return [item.endpoint.value for item in items if item.injection_suspected]
