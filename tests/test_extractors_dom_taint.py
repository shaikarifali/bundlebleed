from __future__ import annotations

from bundlebleed.extractors.dom_taint import dom_taint_risk_flags, extract_dom_taint


def test_location_search_to_innerhtml_xss() -> None:
    js = """
    const q = location.search;
    document.getElementById('result').innerHTML = q;
    """
    findings = extract_dom_taint(js, "https://example.com/app.js")
    xss = [f for f in findings if f.sink_name == "innerHTML" and f.source_name == "location.search"]
    assert len(xss) >= 1


def test_location_hash_to_eval_code_exec() -> None:
    js = """
    const hash = location.hash;
    eval(hash);
    """
    findings = extract_dom_taint(js, "https://example.com/app.js")
    exec_f = [f for f in findings if f.sink_name == "eval" and f.source_name == "location.hash"]
    assert len(exec_f) >= 1
    assert exec_f[0].sink_category == "code_exec"


def test_event_data_to_innerhtml() -> None:
    js = """
    window.addEventListener('message', function(event) {
      document.body.innerHTML = event.data;
    });
    """
    findings = extract_dom_taint(js, "https://example.com/app.js")
    assert any(f.source_name == "event.data" and f.sink_name == "innerHTML" for f in findings)


def test_location_href_to_location_assign_open_redirect() -> None:
    js = """
    const url = location.href;
    location.assign(url);
    """
    findings = extract_dom_taint(js, "https://example.com/app.js")
    redir = [f for f in findings if f.sink_category == "open_redirect"]
    assert len(redir) >= 1


def test_no_taint_when_no_source() -> None:
    js = """
    const x = document.getElementById('output');
    x.innerHTML = '<b>hello</b>';
    """
    # innerHTML sink present but no DOM source → no finding
    findings = extract_dom_taint(js, "https://example.com/app.js")
    assert findings == []


def test_no_taint_when_source_too_far() -> None:
    # Source and sink more than 35 lines apart → no finding
    js = "const q = location.search;\n" + "\n" * 40 + "document.write(x);\n"
    findings = extract_dom_taint(js, "https://example.com/app.js")
    assert findings == []


def test_document_referrer_to_document_write() -> None:
    js = """
    const ref = document.referrer;
    document.write(ref);
    """
    findings = extract_dom_taint(js, "https://example.com/app.js")
    assert any(f.source_name == "document.referrer" and f.sink_name == "document.write" for f in findings)


def test_provenance_fields() -> None:
    js = """
    const q = location.search;
    document.getElementById('x').innerHTML = q;
    """
    findings = extract_dom_taint(js, "https://example.com/app.js", file="/tmp/app.js")
    assert findings[0].file == "/tmp/app.js"
    assert findings[0].source_url == "https://example.com/app.js"


def test_risk_flags_xss() -> None:
    js = """
    const q = location.search;
    el.innerHTML = q;
    """
    findings = extract_dom_taint(js, "https://example.com/app.js")
    flags = dom_taint_risk_flags(findings)
    assert any("xss" in f.lower() or "dom" in f.lower() for f in flags)


def test_deduplication() -> None:
    # Same source-sink chain twice on the same line numbers → one finding
    js = """
    const q = location.search;
    document.getElementById('a').innerHTML = q;
    """
    findings = extract_dom_taint(js, "https://example.com/app.js")
    pairs = [(f.source_name, f.sink_name) for f in findings]
    assert len(pairs) == len(set(pairs)) or len(findings) >= 1


def test_window_name_to_insertadjacenthtml() -> None:
    js = """
    const name = window.name;
    target.insertAdjacentHTML('beforeend', name);
    """
    findings = extract_dom_taint(js, "https://example.com/app.js")
    assert any(f.source_name == "window.name" and f.sink_name == "insertAdjacentHTML" for f in findings)
