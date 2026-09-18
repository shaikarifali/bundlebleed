from __future__ import annotations

from bundlebleed.extractors.patterns import load_endpoint_patterns
from bundlebleed.models import Endpoint


def extract_endpoints(content: str, source_url: str) -> list[Endpoint]:
    """Regex-extract candidate API endpoints/routes from JS content.

    Purely local text processing — no network activity, so this never touches
    ScopeGuard. Deduplicates by (pattern, value, method) so repeated matches
    within one file collapse to a single Endpoint — this is a per-file dedup
    only; deduplicate_endpoints() below merges across files.
    """
    endpoints: list[Endpoint] = []
    seen: set[tuple[str, str, str | None]] = set()

    for pattern in load_endpoint_patterns():
        for match in pattern.regex.finditer(content):
            value = match.group(pattern.group)
            method = pattern.method
            if method is None and pattern.method_group is not None:
                method = match.group(pattern.method_group).upper()
            key = (pattern.name, value, method)
            if key in seen:
                continue
            seen.add(key)
            endpoints.append(
                Endpoint(
                    value=value, pattern_name=pattern.name, source_url=source_url, method=method
                )
            )

    return endpoints


def deduplicate_endpoints(endpoints: list[Endpoint]) -> list[Endpoint]:
    """Merge Endpoints seen in more than one file (a shared webpack chunk, or
    the same literal string in both a raw-URL and a JS-body extraction pass)
    into one, keyed on (pattern_name, value, method).

    The first occurrence's source_url is kept as the primary one — so
    endpoint_id() stays stable across reruns as long as file processing
    order is stable — and every additional file it also appeared in is kept
    in also_seen_in, so nothing is silently dropped; without this, the same
    endpoint used to generate one duplicate Hypothesis per file it happened
    to be referenced from.
    """
    merged: dict[tuple[str, str, str | None], Endpoint] = {}
    order: list[tuple[str, str, str | None]] = []

    for endpoint in endpoints:
        key = (endpoint.pattern_name, endpoint.value, endpoint.method)
        existing = merged.get(key)
        if existing is None:
            merged[key] = endpoint
            order.append(key)
            continue
        if (
            endpoint.source_url != existing.source_url
            and endpoint.source_url not in existing.also_seen_in
        ):
            existing.also_seen_in.append(endpoint.source_url)

    return [merged[key] for key in order]
