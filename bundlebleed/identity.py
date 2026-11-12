from __future__ import annotations

import hashlib

from bundlebleed.models import Endpoint


def stable_id(*parts: str) -> str:
    """Deterministic short id from a tuple of strings — same inputs always
    produce the same id, so cross-references (AI verdict <-> hypothesis)
    and idempotency both hold across runs."""
    raw = ":".join(parts)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def endpoint_id(endpoint: Endpoint) -> str:
    return stable_id(endpoint.pattern_name, endpoint.value, endpoint.source_url)
