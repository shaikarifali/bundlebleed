from __future__ import annotations

from bundlebleed.extractors.patterns import load_dom_sink_patterns, load_dom_source_patterns
from bundlebleed.models import DomFinding


def extract_dom_findings(content: str, source_url: str) -> list[DomFinding]:
    """Flag candidate DOM XSS: a dangerous sink co-occurring with at least one
    user-controllable source *somewhere in the same file* (Phase 3.5).

    This is a co-occurrence heuristic, not a proven data flow — real taint
    tracing is a later stage (the hypothesis engine). If no source pattern
    appears at all, nothing is reported, since a sink alone is unremarkable.
    """
    sources = load_dom_source_patterns()
    present_sources = sorted({s.name for s in sources if s.regex.search(content)})
    if not present_sources:
        return []

    findings: list[DomFinding] = []
    for sink in load_dom_sink_patterns():
        match = sink.regex.search(content)
        if not match:
            continue
        findings.append(
            DomFinding(
                sink_pattern=sink.name,
                sink_value=match.group(0),
                co_occurring_sources=present_sources,
                source_url=source_url,
            )
        )

    return findings
