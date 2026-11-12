from __future__ import annotations

from bundlebleed.extractors.websockets import extract_websocket_findings, websocket_risk_flags


def test_plain_websocket_detected() -> None:
    js = "const ws = new WebSocket('wss://api.example.com/socket');"
    findings = extract_websocket_findings(js, "https://example.com/app.js")
    assert len(findings) >= 1
    assert findings[0].endpoint == "wss://api.example.com/socket"
    assert findings[0].protocol == "websocket"


def test_socketio_detected() -> None:
    js = "const socket = io('https://api.example.com');"
    findings = extract_websocket_findings(js, "https://example.com/app.js")
    assert any(f.protocol == "socketio" for f in findings)


def test_sockjs_detected() -> None:
    js = "var sock = new SockJS('https://api.example.com/sockjs');"
    findings = extract_websocket_findings(js, "https://example.com/app.js")
    assert any(f.protocol == "sockjs" for f in findings)


def test_auth_in_url_flagged() -> None:
    js = "const ws = new WebSocket('wss://api.example.com/socket?token=abc123def456');"
    findings = extract_websocket_findings(js, "https://example.com/app.js")
    assert findings[0].auth_in_url is True


def test_no_auth_in_url() -> None:
    js = "const ws = new WebSocket('wss://api.example.com/socket');"
    findings = extract_websocket_findings(js, "https://example.com/app.js")
    assert findings[0].auth_in_url is False


def test_message_actions_extracted() -> None:
    js = """
    const ws = new WebSocket('wss://api.example.com/socket');
    socket.emit('update_account', data);
    socket.on('account_updated', handler);
    """
    findings = extract_websocket_findings(js, "https://example.com/app.js")
    assert len(findings) >= 1
    all_actions = findings[0].message_actions
    assert "update_account" in all_actions or "account_updated" in all_actions


def test_object_ids_extracted() -> None:
    js = """
    const ws = new WebSocket('wss://api.example.com/socket');
    socket.send(JSON.stringify({ type: 'get_invoice', invoiceId: id }));
    """
    findings = extract_websocket_findings(js, "https://example.com/app.js")
    assert len(findings) >= 1
    assert "invoiceId" in findings[0].object_ids


def test_origin_check_detected() -> None:
    js = """
    const ws = new WebSocket('wss://api.example.com/socket');
    window.addEventListener('message', (event) => {
      if (event.origin !== 'https://example.com') return;
      handleMessage(event.data);
    });
    """
    findings = extract_websocket_findings(js, "https://example.com/app.js")
    assert findings[0].has_origin_check is True


def test_no_origin_check() -> None:
    js = "const ws = new WebSocket('wss://api.example.com/socket');"
    findings = extract_websocket_findings(js, "https://example.com/app.js")
    assert findings[0].has_origin_check is False


def test_risk_flag_auth_in_url() -> None:
    js = "const ws = new WebSocket('wss://api.example.com/ws?token=secret123');"
    findings = extract_websocket_findings(js, "https://example.com/app.js")
    flags = websocket_risk_flags(findings)
    assert any("token" in f.lower() or "auth" in f.lower() or "credentials" in f.lower() for f in flags)


def test_deduplication() -> None:
    js = """
    const ws1 = new WebSocket('wss://api.example.com/socket');
    const ws2 = new WebSocket('wss://api.example.com/socket');
    """
    findings = extract_websocket_findings(js, "https://example.com/app.js")
    assert len(findings) == 1


def test_empty_content() -> None:
    findings = extract_websocket_findings("const x = 1;", "https://example.com/app.js")
    assert findings == []


def test_provenance_fields() -> None:
    js = "const ws = new WebSocket('wss://api.example.com/socket');"
    findings = extract_websocket_findings(js, "https://example.com/app.js", file="/tmp/app.js")
    assert findings[0].file == "/tmp/app.js"
    assert findings[0].source_url == "https://example.com/app.js"
