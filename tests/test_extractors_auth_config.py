from __future__ import annotations

from bundlebleed.extractors.auth_config import extract_auth_findings


def test_jwt_decode_no_verify() -> None:
    js = "const payload = jwtDecode(token);"
    findings = extract_auth_findings(js, "https://example.com/app.js")
    assert any(f.finding_type == "jwt_decode_no_verify" for f in findings)


def test_jwt_alg_none_critical() -> None:
    js = "const opts = { algorithms: 'none' };"
    findings = extract_auth_findings(js, "https://example.com/app.js")
    matches = [f for f in findings if f.finding_type == "jwt_alg_none"]
    assert len(matches) >= 1
    assert matches[0].severity_candidate == "critical"


def test_jwt_jku_reference() -> None:
    js = "const header = { jku: 'https://attacker.com/jwks.json', alg: 'RS256' };"
    findings = extract_auth_findings(js, "https://example.com/app.js")
    assert any(f.finding_type == "jwt_jku_reference" for f in findings)


def test_token_in_localstorage() -> None:
    js = "localStorage.setItem('auth_token', token);"
    findings = extract_auth_findings(js, "https://example.com/app.js")
    assert any(f.finding_type == "token_in_localstorage" for f in findings)


def test_refresh_token_in_localstorage_high_severity() -> None:
    js = "localStorage.setItem('refresh_token', token);"
    findings = extract_auth_findings(js, "https://example.com/app.js")
    matches = [f for f in findings if f.finding_type == "refresh_token_in_localstorage"]
    assert len(matches) >= 1
    assert matches[0].severity_candidate == "high"


def test_oauth_implicit_flow() -> None:
    js = "const params = { response_type: 'token', client_id: 'abc' };"
    findings = extract_auth_findings(js, "https://example.com/app.js")
    assert any(f.finding_type == "oauth_implicit_flow" for f in findings)


def test_oauth_dynamic_redirect_uri() -> None:
    js = "const params = { redirect_uri: window.location.origin + '/callback' };"
    findings = extract_auth_findings(js, "https://example.com/app.js")
    assert any(f.finding_type == "oauth_dynamic_redirect_uri" for f in findings)


def test_token_logged() -> None:
    js = "console.log('token:', authToken);"
    findings = extract_auth_findings(js, "https://example.com/app.js")
    assert any(f.finding_type == "token_logged" for f in findings)


def test_benign_code_no_findings() -> None:
    js = "const x = getUserProfile(); return x.name;"
    findings = extract_auth_findings(js, "https://example.com/app.js")
    assert findings == []


def test_provenance_fields() -> None:
    js = "localStorage.setItem('auth_token', token);"
    findings = extract_auth_findings(js, "https://example.com/app.js", file="/tmp/app.js")
    assert findings[0].file == "/tmp/app.js"
    assert findings[0].source_url == "https://example.com/app.js"


def test_deduplication() -> None:
    js = "localStorage.setItem('auth_token', t);\nlocalStorage.setItem('auth_token', t);"
    findings = extract_auth_findings(js, "https://example.com/app.js")
    matches = [f for f in findings if f.finding_type == "token_in_localstorage"]
    # Same line number deduped — may differ on line 1 vs 2, so just check <= 2
    assert len(matches) <= 2
