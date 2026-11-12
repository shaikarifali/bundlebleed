from __future__ import annotations

import re

from pydantic import BaseModel, Field


class PostMessageFinding(BaseModel):
    """postMessage sender or receiver signal extracted from JS."""

    kind: str                    # "sender" | "receiver"
    target_origin: str | None    # None for receivers; "*" = wildcard (dangerous for senders)
    has_origin_check: bool
    data_sinks: list[str] = Field(default_factory=list)
    file: str
    line: int
    source_url: str


# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

# postMessage calls: contentWindow.postMessage(data, origin) or window.postMessage(...)
# First arg may be an object literal, string, or variable — allow nested {} and quoted strings.
_POSTMSG_SEND_RE = re.compile(
    r"""\.postMessage\s*\(\s*"""
    r"""(?:[^()'"`{},]|(?:'[^']*'|"[^"]*"|`[^`]*`)|(?:\{[^{}]*\}))*"""
    r""",\s*(?P<origin>['"`]([^'"`]*?)['"`]|\w[\w.]*)\s*\)""",
    re.IGNORECASE,
)

# addEventListener('message', handler)
_MSG_LISTENER_RE = re.compile(
    r"""addEventListener\s*\(\s*['"]message['"]\s*,""",
    re.IGNORECASE,
)

# Origin validation inside a message handler
_ORIGIN_CHECK_RE = re.compile(
    r"""event\s*\.\s*origin\s*(?:!==|===|==|!=|<|>)\s*['"`]|
        (?:allowedOrigins?|trustedOrigins?|whitelist|ALLOWED_ORIGINS)\s*\.
        (?:includes?|has|indexOf)\s*\(\s*event|
        event\s*\.\s*origin\s+(?:in|===)\s+\w""",
    re.VERBOSE | re.IGNORECASE,
)

# Data sinks reachable from event.data
_DATA_SINK_PATTERNS: dict[str, re.Pattern] = {
    "eval": re.compile(r"""\beval\s*\(\s*event\s*\.\s*data"""),
    "innerHTML": re.compile(r"""\.innerHTML\s*=\s*.*?event\s*\.\s*data"""),
    "location": re.compile(r"""(?:location\s*\.?\s*href|location\.assign|location\.replace)\s*.*?event\s*\.\s*data"""),
    "JSON.parse": re.compile(r"""JSON\s*\.\s*parse\s*\(\s*event\s*\.\s*data"""),
    "document.write": re.compile(r"""document\s*\.\s*write\s*\(\s*event\s*\.\s*data"""),
    "Function": re.compile(r"""(?:new\s+Function|Function\.prototype\.call)\s*\(\s*event\s*\.\s*data"""),
}

# Proximity window: how many lines around a listener/sender to check for origin checks and sinks
_WINDOW = 25


def _line_number(content: str, pos: int) -> int:
    return content.count("\n", 0, pos) + 1


def _context_around(lines: list[str], line_idx: int, window: int) -> str:
    lo = max(0, line_idx - window)
    hi = min(len(lines), line_idx + window + 1)
    return "\n".join(lines[lo:hi])


def extract_postmessage_findings(
    content: str, source_url: str, file: str = ""
) -> list[PostMessageFinding]:
    """Find postMessage senders and receivers in JS.

    For senders: captures target origin; wildcard '*' is flagged.
    For receivers: checks whether the handler validates event.origin and what
    it does with event.data (the data sinks list).

    Two findings at the same line are collapsed to one.
    """
    path = file or source_url
    lines = content.split("\n")
    findings: list[PostMessageFinding] = []
    seen: set[tuple[str, int]] = set()

    # --- Senders ---
    for m in _POSTMSG_SEND_RE.finditer(content):
        line_idx = content.count("\n", 0, m.start())
        raw_origin = m.group("origin").strip("'`\" ")
        key = ("sender", line_idx)
        if key in seen:
            continue
        seen.add(key)
        findings.append(
            PostMessageFinding(
                kind="sender",
                target_origin=raw_origin or None,
                has_origin_check=False,  # n/a for senders
                data_sinks=[],
                file=path,
                line=line_idx + 1,
                source_url=source_url,
            )
        )

    # --- Receivers ---
    for m in _MSG_LISTENER_RE.finditer(content):
        line_idx = content.count("\n", 0, m.start())
        key = ("receiver", line_idx)
        if key in seen:
            continue
        seen.add(key)
        ctx = _context_around(lines, line_idx, _WINDOW)
        has_origin_check = bool(_ORIGIN_CHECK_RE.search(ctx))
        sinks = [name for name, pat in _DATA_SINK_PATTERNS.items() if pat.search(ctx)]
        findings.append(
            PostMessageFinding(
                kind="receiver",
                target_origin=None,
                has_origin_check=has_origin_check,
                data_sinks=sinks,
                file=path,
                line=line_idx + 1,
                source_url=source_url,
            )
        )

    return findings


def postmessage_risk_flags(findings: list[PostMessageFinding]) -> list[str]:
    """Human-readable risk summaries for postMessage findings."""
    flags: list[str] = []
    wildcards = [f for f in findings if f.kind == "sender" and f.target_origin == "*"]
    if wildcards:
        flags.append(
            f"postMessage with wildcard targetOrigin ('*') at {len(wildcards)} site(s) — "
            "sensitive data may be received by any frame"
        )
    unchecked_receivers = [
        f for f in findings if f.kind == "receiver" and not f.has_origin_check
    ]
    if unchecked_receivers:
        flags.append(
            f"{len(unchecked_receivers)} message receiver(s) with no event.origin check — "
            "cross-origin messages accepted from any sender"
        )
    receivers_with_sinks = [
        f for f in findings if f.kind == "receiver" and f.data_sinks
    ]
    if receivers_with_sinks:
        all_sinks = {s for f in receivers_with_sinks for s in f.data_sinks}
        flags.append(
            f"event.data flows into dangerous sinks: {', '.join(sorted(all_sinks))} — "
            "potential postMessage XSS or open redirect"
        )
    return flags
