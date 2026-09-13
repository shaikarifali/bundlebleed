from __future__ import annotations

import itertools
import re

from bundlebleed.extractors.patterns import load_parameter_keywords
from bundlebleed.models import ParameterFinding

_DECLARATION_RE = re.compile(r"(?:const|let|var)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=")
_QUERY_PARAM_RE = re.compile(r"[?&]([a-zA-Z_][a-zA-Z0-9_\-]*)=")
_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


def tokenize_identifier(name: str) -> list[str]:
    """Split an identifier into lowercase words on '_'/'-' and camelCase
    boundaries, so keyword matching is whole-word ("id" in "userId") instead
    of substring ("id" in "hidden", or "valid"/"void"). Shared with the
    hypothesis engine's query-string IDOR-shape check."""
    words: list[str] = []
    for part in re.split(r"[_\-$]", name):
        words.extend(_CAMEL_BOUNDARY.split(part))
    return [w.lower() for w in words if w]


def extract_parameters(content: str, source_url: str) -> list[ParameterFinding]:
    """Extract names that look security-interesting (id/token/role/admin/...)
    as a fuzzing/review wordlist (Phase 3.4): JS variable declarations
    (`const userId = ...`) and URL query-string keys (`?productId=1`) alike —
    a plain page link is just as worth flagging as a JS-declared variable."""
    keywords = set(load_parameter_keywords())
    seen: set[str] = set()
    findings: list[ParameterFinding] = []

    candidates = itertools.chain(
        _DECLARATION_RE.finditer(content), _QUERY_PARAM_RE.finditer(content)
    )
    for match in candidates:
        name = match.group(1)
        if name in seen:
            continue
        if not any(word in keywords for word in tokenize_identifier(name)):
            continue
        seen.add(name)
        findings.append(ParameterFinding(name=name, source_url=source_url))

    return findings
