from __future__ import annotations

import re

from bundlebleed.models import SubdomainFinding
from bundlebleed.scope.models import ScopeConfig
from bundlebleed.scope.validator import is_in_scope

_LABEL = r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"


def extract_subdomains(
    content: str, source_url: str, scope_config: ScopeConfig
) -> list[SubdomainFinding]:
    """Find hostnames in `content` that are subdomains of one of the scan's
    target domains (Phase 3.3), and classify each against current scope:

    - matches the loaded scope (wildcard or an explicit exact entry) -> in_scope
    - otherwise -> flagged for manual review, never auto-tested (still v0.2:
      no active testing of any kind happens here or anywhere yet)
    """
    base_domains = {entry.domain for entry in scope_config.in_scope}
    if not base_domains:
        return []

    seen: set[str] = set()
    findings: list[SubdomainFinding] = []

    for base in sorted(base_domains):
        pattern = re.compile(rf"(?:{_LABEL}\.)+{re.escape(base)}\b", re.IGNORECASE)
        for match in pattern.finditer(content):
            hostname = match.group(0).lower()
            if hostname in seen:
                continue
            seen.add(hostname)

            decision = is_in_scope(hostname, scope_config)
            in_scope = decision.decision.value == "ALLOW"
            note = (
                "in scope: " + decision.reason
                if in_scope
                else "discovered, flagged for manual review: " + decision.reason
            )
            findings.append(
                SubdomainFinding(
                    domain=hostname, source_url=source_url, in_scope=in_scope, note=note
                )
            )

    return findings
