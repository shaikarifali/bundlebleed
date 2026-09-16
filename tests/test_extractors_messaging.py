from __future__ import annotations

from bundlebleed.extractors.messaging import (
    extract_postmessage_findings,
    extract_websocket_findings,
)


def test_message_listener_with_no_origin_check_is_flagged() -> None:
    content = "window.addEventListener('message', function(e) { eval(e.data); });"
    findings = extract_postmessage_findings(content, source_url="https://e.com/app.js")
    assert len(findings) == 1
    assert findings[0].source_url == "https://e.com/app.js"


def test_onmessage_assignment_with_no_origin_check_is_flagged() -> None:
    content = "window.onmessage = function(e) { document.write(e.data); };"
    findings = extract_postmessage_findings(content, source_url="https://e.com/app.js")
    assert len(findings) == 1


def test_message_listener_with_origin_check_is_not_flagged() -> None:
    content = (
        "window.addEventListener('message', function(e) {"
        "if (e.origin !== 'https://trusted.example.com') return;"
        "handle(e.data); });"
    )
    findings = extract_postmessage_findings(content, source_url="https://e.com/app.js")
    assert findings == []


def test_no_message_listener_produces_no_finding() -> None:
    findings = extract_postmessage_findings("const x = 1;", source_url="https://e.com/app.js")
    assert findings == []


def test_websocket_with_no_token_hint_is_flagged() -> None:
    content = "const ws = new WebSocket('wss://e.com/socket');"
    findings = extract_websocket_findings(content, source_url="https://e.com/app.js")
    assert len(findings) == 1


def test_websocket_with_token_in_url_is_not_flagged() -> None:
    content = "const ws = new WebSocket('wss://e.com/socket?token=abc123');"
    findings = extract_websocket_findings(content, source_url="https://e.com/app.js")
    assert findings == []


def test_websocket_with_nearby_auth_header_setup_is_not_flagged() -> None:
    content = "const ws = new WebSocket('wss://e.com/socket'); ws.auth = getAuthToken();"
    findings = extract_websocket_findings(content, source_url="https://e.com/app.js")
    assert findings == []


def test_multiple_websocket_calls_each_evaluated_independently() -> None:
    # The two calls are separated by more than the detection window so an
    # auth hint near the second call can't bleed into the first's window.
    filler = "// unrelated code\n" * 20
    content = f"new WebSocket('wss://e.com/public');{filler}new WebSocket('wss://e.com/private?token=xyz');"
    findings = extract_websocket_findings(content, source_url="https://e.com/app.js")
    assert len(findings) == 1
