from __future__ import annotations

import re

from bundlebleed.models import PostMessageFinding, WebSocketFinding

_MESSAGE_LISTENER_RE = re.compile(r"addEventListener\(\s*['\"]message['\"]|\.onmessage\s*=")
_ORIGIN_CHECK_RE = re.compile(r"\.origin\b")

_WEBSOCKET_RE = re.compile(r"new\s+WebSocket\s*\(")
_AUTH_HINT_RE = re.compile(r"(?i)token|auth")
_WEBSOCKET_WINDOW = 200


def extract_postmessage_findings(content: str, source_url: str) -> list[PostMessageFinding]:
    """Flag a `message` event listener registered with no `.origin` check
    anywhere in the same file — a whole-file co-occurrence heuristic, like
    the DOM sink/source engine, not a proven data flow.

    Precision over recall: a large bundle checking `.origin` anywhere for
    an unrelated reason means a real bug here goes unflagged rather than
    the tool over-flagging every message listener it finds.
    """
    match = _MESSAGE_LISTENER_RE.search(content)
    if not match or _ORIGIN_CHECK_RE.search(content):
        return []
    return [
        PostMessageFinding(
            source_url=source_url,
            snippet_preview=content[match.start() : match.start() + 80],
        )
    ]


def extract_websocket_findings(content: str, source_url: str) -> list[WebSocketFinding]:
    """Flag each `new WebSocket(...)` call with no visible token/auth hint
    in the ~200 chars after it — a candidate for missing-Origin-check
    Cross-Site WebSocket Hijacking if the server relies on ambient cookie
    auth alone. A local window (not whole-file) is used here since a
    connection URL/options object is typically compact and nearby, unlike
    a message-handler body."""
    findings: list[WebSocketFinding] = []
    for match in _WEBSOCKET_RE.finditer(content):
        window = content[match.start() : match.start() + _WEBSOCKET_WINDOW]
        if not _AUTH_HINT_RE.search(window):
            findings.append(WebSocketFinding(source_url=source_url, snippet_preview=window[:80]))
    return findings
