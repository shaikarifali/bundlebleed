from __future__ import annotations

from bundlebleed.extractors.workers import extract_worker_findings, worker_risk_flags


def test_service_worker_registration_detected() -> None:
    js = "navigator.serviceWorker.register('/sw.js');"
    findings = extract_worker_findings(js, "https://example.com/app.js")
    sw = [f for f in findings if f.worker_type == "service_worker"]
    assert len(sw) >= 1
    assert sw[0].worker_url == "/sw.js"


def test_service_worker_with_fetch_intercept() -> None:
    js = """
    navigator.serviceWorker.register('/sw.js');
    self.addEventListener('fetch', function(event) {
      event.respondWith(fetch(event.request));
    });
    """
    findings = extract_worker_findings(js, "https://example.com/sw.js")
    sw = [f for f in findings if f.worker_type == "service_worker"]
    assert any(f.has_fetch_intercept for f in sw)


def test_skip_waiting_flagged() -> None:
    js = """
    navigator.serviceWorker.register('/sw.js');
    self.skipWaiting();
    """
    findings = extract_worker_findings(js, "https://example.com/app.js")
    sw = [f for f in findings if f.worker_type == "service_worker"]
    assert any(f.has_skip_waiting for f in sw)


def test_web_worker_detected() -> None:
    js = "const worker = new Worker('/workers/crypto.js');"
    findings = extract_worker_findings(js, "https://example.com/app.js")
    ww = [f for f in findings if f.worker_type == "web_worker"]
    assert len(ww) >= 1
    assert ww[0].worker_url == "/workers/crypto.js"


def test_blob_worker_detected() -> None:
    js = """
    const blob = new Blob([code], { type: 'application/javascript' });
    const worker = new Worker(URL.createObjectURL(blob));
    """
    findings = extract_worker_findings(js, "https://example.com/app.js")
    blob = [f for f in findings if f.is_inline_blob]
    assert len(blob) >= 1


def test_shared_worker_detected() -> None:
    js = "const sw = new SharedWorker('/shared.js');"
    findings = extract_worker_findings(js, "https://example.com/app.js")
    shared = [f for f in findings if f.worker_type == "shared_worker"]
    assert len(shared) >= 1
    assert shared[0].worker_url == "/shared.js"


def test_importscripts_detected() -> None:
    js = """
    navigator.serviceWorker.register('/sw.js');
    importScripts('https://cdn.example.com/lib.js', '/local.js');
    """
    findings = extract_worker_findings(js, "https://example.com/sw.js")
    sw = [f for f in findings if f.worker_type == "service_worker"]
    assert any(f.has_importscripts for f in sw)
    all_urls = {u for f in sw for u in f.importscripts_urls}
    assert "https://cdn.example.com/lib.js" in all_urls


def test_risk_flag_fetch_intercept() -> None:
    js = """
    navigator.serviceWorker.register('/sw.js');
    self.addEventListener('fetch', handler);
    """
    findings = extract_worker_findings(js, "https://example.com/app.js")
    flags = worker_risk_flags(findings)
    assert any("fetch" in f.lower() or "intercept" in f.lower() for f in flags)


def test_risk_flag_blob_worker() -> None:
    js = "const w = new Worker(URL.createObjectURL(new Blob([src])));"
    findings = extract_worker_findings(js, "https://example.com/app.js")
    flags = worker_risk_flags(findings)
    assert any("blob" in f.lower() or "inline" in f.lower() for f in flags)


def test_empty_content() -> None:
    findings = extract_worker_findings("const x = 1;", "https://example.com/app.js")
    assert findings == []


def test_provenance_fields() -> None:
    js = "navigator.serviceWorker.register('/sw.js');"
    findings = extract_worker_findings(js, "https://example.com/app.js", file="/tmp/app.js")
    assert findings[0].file == "/tmp/app.js"
    assert findings[0].source_url == "https://example.com/app.js"
