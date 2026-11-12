from __future__ import annotations

from bundlebleed.extractors.postmessage import (
    extract_postmessage_findings,
    postmessage_risk_flags,
)


def test_sender_wildcard_origin_detected() -> None:
    js = "window.postMessage({ type: 'token', value: authToken }, '*');"
    findings = extract_postmessage_findings(js, "https://example.com/app.js")
    senders = [f for f in findings if f.kind == "sender"]
    assert len(senders) >= 1
    assert senders[0].target_origin == "*"


def test_sender_specific_origin() -> None:
    js = "iframe.contentWindow.postMessage(data, 'https://trusted.com');"
    findings = extract_postmessage_findings(js, "https://example.com/app.js")
    senders = [f for f in findings if f.kind == "sender"]
    assert len(senders) >= 1
    assert senders[0].target_origin == "https://trusted.com"


def test_receiver_detected() -> None:
    js = """
    window.addEventListener('message', function(event) {
      handleMessage(event.data);
    });
    """
    findings = extract_postmessage_findings(js, "https://example.com/app.js")
    receivers = [f for f in findings if f.kind == "receiver"]
    assert len(receivers) >= 1


def test_receiver_with_origin_check() -> None:
    js = """
    window.addEventListener('message', function(event) {
      if (event.origin !== 'https://example.com') return;
      handleMessage(event.data);
    });
    """
    findings = extract_postmessage_findings(js, "https://example.com/app.js")
    receivers = [f for f in findings if f.kind == "receiver"]
    assert receivers[0].has_origin_check is True


def test_receiver_without_origin_check() -> None:
    js = """
    window.addEventListener('message', function(event) {
      doSomething(event.data);
    });
    """
    findings = extract_postmessage_findings(js, "https://example.com/app.js")
    receivers = [f for f in findings if f.kind == "receiver"]
    assert receivers[0].has_origin_check is False


def test_data_sink_eval_detected() -> None:
    js = """
    window.addEventListener('message', function(event) {
      eval(event.data);
    });
    """
    findings = extract_postmessage_findings(js, "https://example.com/app.js")
    receivers = [f for f in findings if f.kind == "receiver"]
    assert "eval" in receivers[0].data_sinks


def test_data_sink_innerhtml_detected() -> None:
    js = """
    window.addEventListener('message', function(event) {
      document.getElementById('x').innerHTML = event.data;
    });
    """
    findings = extract_postmessage_findings(js, "https://example.com/app.js")
    receivers = [f for f in findings if f.kind == "receiver"]
    assert "innerHTML" in receivers[0].data_sinks


def test_risk_flag_wildcard() -> None:
    js = "window.postMessage(secret, '*');"
    findings = extract_postmessage_findings(js, "https://example.com/app.js")
    flags = postmessage_risk_flags(findings)
    assert any("wildcard" in f.lower() or "*" in f for f in flags)


def test_risk_flag_no_origin_check() -> None:
    js = "window.addEventListener('message', function(e) { use(e.data); });"
    findings = extract_postmessage_findings(js, "https://example.com/app.js")
    flags = postmessage_risk_flags(findings)
    assert any("origin" in f.lower() for f in flags)


def test_empty_content() -> None:
    findings = extract_postmessage_findings("const x = 1;", "https://example.com/app.js")
    assert findings == []


def test_provenance_fields() -> None:
    js = "window.addEventListener('message', handler);"
    findings = extract_postmessage_findings(js, "https://example.com/app.js", file="/tmp/app.js")
    assert findings[0].file == "/tmp/app.js"
    assert findings[0].source_url == "https://example.com/app.js"
