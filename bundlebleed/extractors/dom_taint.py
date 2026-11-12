from __future__ import annotations

import re

from pydantic import BaseModel


class DomTaintFinding(BaseModel):
    """Source-to-sink data flow signal in JS (proximity-based, not true CFG taint)."""

    source_name: str      # e.g. "location.search", "event.data"
    source_line: int
    sink_name: str        # e.g. "innerHTML", "eval"
    sink_line: int
    sink_category: str    # "xss" | "code_exec" | "open_redirect" | "script_injection"
    variable_bridge: str | None  # variable connecting source to sink, if detectable
    file: str
    source_url: str


# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------

_TAINT_SOURCES: dict[str, re.Pattern] = {
    "location.search": re.compile(r"\blocation\s*\.\s*search\b"),
    "location.hash": re.compile(r"\blocation\s*\.\s*hash\b"),
    "location.href": re.compile(r"\blocation\s*\.\s*href\b"),
    "document.URL": re.compile(r"\bdocument\s*\.\s*URL\b"),
    "document.referrer": re.compile(r"\bdocument\s*\.\s*referrer\b"),
    "window.name": re.compile(r"\bwindow\s*\.\s*name\b"),
    "event.data": re.compile(r"\bevent\s*\.\s*data\b"),
    "document.cookie": re.compile(r"\bdocument\s*\.\s*cookie\b"),
    "URLSearchParams": re.compile(r"\bnew\s+URLSearchParams\s*\("),
    "localStorage.getItem": re.compile(r"\blocalStorage\s*\.\s*getItem\s*\("),
}

# ---------------------------------------------------------------------------
# Sinks
# ---------------------------------------------------------------------------

_TAINT_SINKS: dict[str, tuple[re.Pattern, str]] = {
    "innerHTML": (re.compile(r"\.\s*innerHTML\s*[+]?=(?!=)"), "xss"),
    "outerHTML": (re.compile(r"\.\s*outerHTML\s*[+]?=(?!=)"), "xss"),
    "document.write": (re.compile(r"\bdocument\s*\.\s*write\s*\("), "xss"),
    "insertAdjacentHTML": (re.compile(r"\.\s*insertAdjacentHTML\s*\("), "xss"),
    "eval": (re.compile(r"\beval\s*\("), "code_exec"),
    "Function": (re.compile(r"\bnew\s+Function\s*\("), "code_exec"),
    "setTimeout_str": (re.compile(r"\bsetTimeout\s*\(\s*['\"`]"), "code_exec"),
    "setInterval_str": (re.compile(r"\bsetInterval\s*\(\s*['\"`]"), "code_exec"),
    "location.href_assign": (re.compile(r"\blocation\s*\.\s*href\s*=(?!=)"), "open_redirect"),
    "location.assign": (re.compile(r"\blocation\s*\.\s*assign\s*\("), "open_redirect"),
    "location.replace": (re.compile(r"\blocation\s*\.\s*replace\s*\("), "open_redirect"),
    "src_assign": (re.compile(r"\bsrc\s*=(?!=)\s*(?!['\"](?:/|\.\/|https?://[a-z]))"), "script_injection"),
}

# How many lines around a source to look for a sink (or vice versa).
_TAINT_WINDOW = 35

# Variable assignment: const/let/var <name> = <expr with source>
_VAR_ASSIGN_RE = re.compile(
    r"""(?:const|let|var)\s+([a-zA-Z_$][\w$]*)\s*="""
)


def _line_number(content: str, pos: int) -> int:
    return content.count("\n", 0, pos) + 1


def extract_dom_taint(
    content: str, source_url: str, file: str = ""
) -> list[DomTaintFinding]:
    """Find source-to-sink DOM taint chains via proximity analysis.

    Strategy:
    1. Record every source occurrence with its line index.
    2. For every sink occurrence, check whether any source falls within
       _TAINT_WINDOW lines.  If so, emit a finding.
    3. Attempt to extract a variable name bridging source → sink from the
       context lines (best-effort, not a guarantee of real data flow).

    Two sinks of different types at the same line from the same source are
    each reported independently.  Exact duplicates (same source name + line +
    sink name + sink line) are suppressed.
    """
    path = file or source_url
    lines = content.split("\n")

    # (line_idx, source_name) for every source occurrence
    source_hits: list[tuple[int, str]] = []
    for src_name, pat in _TAINT_SOURCES.items():
        for m in pat.finditer(content):
            source_hits.append((content.count("\n", 0, m.start()), src_name))

    if not source_hits:
        return []

    findings: list[DomTaintFinding] = []
    seen: set[tuple[int, str, int, str]] = set()

    for sink_name, (sink_pat, sink_cat) in _TAINT_SINKS.items():
        for sm in sink_pat.finditer(content):
            sink_idx = content.count("\n", 0, sm.start())

            # Nearest source within window
            candidates = [
                s for s in source_hits if abs(s[0] - sink_idx) <= _TAINT_WINDOW
            ]
            if not candidates:
                continue
            nearest_src = min(candidates, key=lambda s: abs(s[0] - sink_idx))

            key = (nearest_src[0], nearest_src[1], sink_idx, sink_name)
            if key in seen:
                continue
            seen.add(key)

            # Variable bridge: scan context lines for const/let/var assignment
            lo = max(0, min(nearest_src[0], sink_idx))
            hi = min(len(lines), max(nearest_src[0], sink_idx) + 1)
            context = "\n".join(lines[lo:hi])
            bridge: str | None = None
            vm = _VAR_ASSIGN_RE.search(context)
            if vm:
                bridge = vm.group(1)

            findings.append(
                DomTaintFinding(
                    source_name=nearest_src[1],
                    source_line=nearest_src[0] + 1,
                    sink_name=sink_name,
                    sink_line=sink_idx + 1,
                    sink_category=sink_cat,
                    variable_bridge=bridge,
                    file=path,
                    source_url=source_url,
                )
            )

    return findings


def dom_taint_risk_flags(findings: list[DomTaintFinding]) -> list[str]:
    """Human-readable risk summaries for a set of DOM taint findings."""
    flags: list[str] = []
    xss = [f for f in findings if f.sink_category == "xss"]
    exec_ = [f for f in findings if f.sink_category == "code_exec"]
    redir = [f for f in findings if f.sink_category == "open_redirect"]
    if xss:
        srcs = {f.source_name for f in xss}
        sinks = {f.sink_name for f in xss}
        flags.append(f"DOM XSS candidates: {len(xss)} source→sink chains ({', '.join(sorted(srcs))} → {', '.join(sorted(sinks))})")
    if exec_:
        flags.append(f"Code execution sinks reachable from DOM sources: {len(exec_)} chains ({', '.join(sorted({f.sink_name for f in exec_}))})")
    if redir:
        flags.append(f"Open redirect candidates: {len(redir)} source→location sink chains")
    event_data = [f for f in findings if f.source_name == "event.data"]
    if event_data:
        flags.append(f"event.data (postMessage) flows into {len(event_data)} sinks — potential DOM clobbering or postMessage XSS")
    return flags
