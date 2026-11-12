from __future__ import annotations

from bundlebleed.extractors.patterns import load_endpoint_patterns
from bundlebleed.models import Endpoint


def extract_endpoints(content: str, source_url: str) -> list[Endpoint]:
    """Regex-extract candidate API endpoints/routes from JS content.

    Purely local text processing — no network activity, so this never touches
    ScopeGuard. Deduplicates by (pattern, value) so repeated matches within one
    file collapse to a single Endpoint.
    """
    endpoints: list[Endpoint] = []
    seen: set[tuple[str, str]] = set()

    for pattern in load_endpoint_patterns():
        for match in pattern.regex.finditer(content):
            value = match.group(pattern.group)
            key = (pattern.name, value)
            if key in seen:
                continue
            seen.add(key)
            endpoints.append(
                Endpoint(value=value, pattern_name=pattern.name, source_url=source_url)
            )

    return endpoints
