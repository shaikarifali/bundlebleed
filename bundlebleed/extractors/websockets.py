from __future__ import annotations

import re

from pydantic import BaseModel, Field


class WebSocketFinding(BaseModel):
    """A WebSocket connection discovered in JS source."""

    endpoint: str
    protocol: str  # "websocket" | "socketio" | "sockjs" | "stomp" | "graphql-ws"
    auth_in_url: bool
    message_actions: list[str] = Field(default_factory=list)
    object_ids: list[str] = Field(default_factory=list)
    has_origin_check: bool = False
    file: str
    line: int
    source_url: str


# --- patterns ---

_WS_NEW_RE = re.compile(
    r"""new\s+WebSocket\s*\(\s*['"](wss?://[^'"]+)['"]\s*""",
    re.IGNORECASE,
)
_WS_VAR_RE = re.compile(
    r"""(?:wsUrl|socketUrl|wsEndpoint|ws_url|socket_url)\s*[:=]\s*['"](wss?://[^'"]+)['"]\s*""",
    re.IGNORECASE,
)
_WS_DYNAMIC_RE = re.compile(
    r"""new\s+WebSocket\s*\(\s*([^)'"]{5,60})\s*\)""",
)

_SOCKETIO_RE = re.compile(r"""io\s*\(\s*['"](https?://[^'"]+)['"]\s*""", re.IGNORECASE)
_SOCKETIO_NOURL_RE = re.compile(r"\bio\s*\(\s*\)")
_SOCKJS_RE = re.compile(r"""new\s+SockJS\s*\(\s*['"](https?://[^'"]+)['"]\s*""", re.IGNORECASE)
_STOMP_RE = re.compile(r"""Stomp\.over\s*\(|StompClient\b""", re.IGNORECASE)
_GQL_WS_RE = re.compile(r"""createClient\s*\(.*graphql.*ws|graphql-ws|subscriptionClient""", re.IGNORECASE | re.DOTALL)

# Auth in URL signals
_AUTH_URL_RE = re.compile(r"""[?&](token|auth|key|jwt|access_token|api_key)=[^&'"]+""", re.IGNORECASE)

# Message action/type patterns
_MSG_EMIT_RE = re.compile(r"""\.emit\s*\(\s*['"]([\w.\-:]+)['"]\s*""")
_MSG_ON_RE = re.compile(r"""\.on\s*\(\s*['"]([\w.\-:]+)['"]\s*""")
_MSG_SEND_TYPE_RE = re.compile(r"""(?:type|action|event)\s*:\s*['"]([\w.\-:]+)['"]\s*""")

# Object ID references in message payloads
_OBJ_ID_RE = re.compile(
    r"""\b(userId|accountId|tenantId|orgId|organizationId|memberId|invoiceId|orderId|documentId)\b""",
    re.IGNORECASE,
)

# Origin check patterns
_ORIGIN_CHECK_RE = re.compile(
    r"""event\.origin\s*[!=]==?\s*|allowedOrigins\s*\.\s*includes\s*\(\s*event\b""",
    re.IGNORECASE,
)


def _line_number(content: str, pos: int) -> int:
    return content.count("\n", 0, pos) + 1


def _snippet(content: str, pos: int, window: int = 300) -> str:
    return content[pos : pos + window]


def extract_websocket_findings(
    content: str, source_url: str, file: str = ""
) -> list[WebSocketFinding]:
    """Extract WebSocket and real-time API endpoints from JS source.

    Detects plain WebSocket, Socket.IO, SockJS, STOMP, and graphql-ws.
    For each connection:
    - Extracts endpoint URL
    - Flags auth tokens in the URL (credential in WS handshake)
    - Collects message action/type names for protocol mapping
    - Flags object IDs in message payloads (BOLA candidate)
    - Checks for origin validation on message receivers

    Pure static analysis — no connections are made.
    """
    path = file or source_url
    seen: set[str] = set()
    results: list[WebSocketFinding] = []

    has_origin_check = bool(_ORIGIN_CHECK_RE.search(content))
    actions = list(dict.fromkeys(
        m.group(1) for m in _MSG_EMIT_RE.finditer(content)
    ))
    on_events = list(dict.fromkeys(
        m.group(1) for m in _MSG_ON_RE.finditer(content)
    ))
    type_values = list(dict.fromkeys(
        m.group(1) for m in _MSG_SEND_TYPE_RE.finditer(content)
    ))
    all_actions = list(dict.fromkeys(actions + on_events + type_values))[:30]
    obj_ids = list(dict.fromkeys(m.group(1) for m in _OBJ_ID_RE.finditer(content)))

    def _add(endpoint: str, protocol: str, line_no: int) -> None:
        key = (endpoint, protocol)
        if key in seen:
            return
        seen.add(key)
        auth_in_url = bool(_AUTH_URL_RE.search(endpoint))
        results.append(
            WebSocketFinding(
                endpoint=endpoint,
                protocol=protocol,
                auth_in_url=auth_in_url,
                message_actions=all_actions,
                object_ids=obj_ids,
                has_origin_check=has_origin_check,
                file=path,
                line=line_no,
                source_url=source_url,
            )
        )

    for m in _WS_NEW_RE.finditer(content):
        _add(m.group(1), "websocket", _line_number(content, m.start()))

    for m in _WS_VAR_RE.finditer(content):
        _add(m.group(1), "websocket", _line_number(content, m.start()))

    for m in _WS_DYNAMIC_RE.finditer(content):
        endpoint = f"dynamic:{m.group(1).strip()[:60]}"
        _add(endpoint, "websocket", _line_number(content, m.start()))

    for m in _SOCKETIO_RE.finditer(content):
        _add(m.group(1), "socketio", _line_number(content, m.start()))

    if _SOCKETIO_NOURL_RE.search(content) and not _SOCKETIO_RE.search(content):
        line_no = _line_number(content, _SOCKETIO_NOURL_RE.search(content).start())  # type: ignore[union-attr]
        _add("/socket.io", "socketio", line_no)

    for m in _SOCKJS_RE.finditer(content):
        _add(m.group(1), "sockjs", _line_number(content, m.start()))

    if _STOMP_RE.search(content):
        line_no = _line_number(content, _STOMP_RE.search(content).start())  # type: ignore[union-attr]
        _add("/stomp", "stomp", line_no)

    if _GQL_WS_RE.search(content):
        line_no = _line_number(content, _GQL_WS_RE.search(content).start())  # type: ignore[union-attr]
        _add("/graphql", "graphql-ws", line_no)

    return results


def websocket_risk_flags(findings: list[WebSocketFinding]) -> list[str]:
    """Return human-readable risk signals from WebSocket findings.

    Investigation leads only — not confirmed vulnerabilities.
    """
    flags: list[str] = []
    for f in findings:
        if f.auth_in_url:
            flags.append(
                f"WebSocket endpoint '{f.endpoint}' at {f.file}:{f.line} has auth "
                f"token in URL — credentials in WS handshake are logged by proxies"
            )
        if f.object_ids and not f.has_origin_check:
            flags.append(
                f"WebSocket at '{f.endpoint}' references object IDs {f.object_ids} "
                f"with no origin validation — potential CSWSH + BOLA"
            )
        if not f.has_origin_check and f.protocol in ("websocket", "socketio"):
            flags.append(
                f"WebSocket at '{f.endpoint}' — no event.origin check found in this file; "
                f"verify CSRF / CSWSH protection"
            )
    return flags
