from __future__ import annotations

# Heuristic only, never a guarantee — the system prompts already forbid
# exploitative/destructive language. This flags (never silently strips) any
# drafted text that reads like one anyway, so a human reviews it before
# ever using it (CLAUDE.md Invariant 1 & 4). Shared by every AI-writing task
# (report drafting, attack-chain suggestion, ...) so the list is maintained
# in exactly one place.
PROHIBITED_KEYWORDS = (
    "drop table",
    "brute force",
    "brute-force",
    "default password",
    "sql injection payload",
    "rm -rf",
    "delete from",
    " fuzz",
)


def flagged_unsafe_text(texts: list[str]) -> list[str]:
    """Return the subset of `texts` that reads like an exploitation/
    destructive instruction despite the prompt forbidding it."""
    return [text for text in texts if any(kw in text.lower() for kw in PROHIBITED_KEYWORDS)]
