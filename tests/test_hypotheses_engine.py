from __future__ import annotations

from datetime import datetime

from bundlebleed.hypotheses.engine import generate_hypotheses
from bundlebleed.identity import endpoint_id
from bundlebleed.models import (
    AIEndpointVerdict,
    CorsMisconfiguration,
    DomFinding,
    Endpoint,
    ScanResult,
    SchemaDiscrepancy,
    Secret,
    SubdomainFinding,
    ThirdPartyScript,
)


def _result(**kwargs: object) -> ScanResult:
    return ScanResult(scan_run_id="run-1", started_at=datetime.now(), **kwargs)  # type: ignore[arg-type]


def test_endpoint_with_numeric_id_generates_idor_hypothesis() -> None:
    endpoint = Endpoint(
        value="/api/v1/users/123", pattern_name="rest_api_path", source_url="https://e.com/app.js"
    )
    hypotheses = generate_hypotheses(_result(endpoints=[endpoint]))

    assert len(hypotheses) == 1
    assert hypotheses[0].id == endpoint_id(endpoint)
    assert "IDOR" in hypotheses[0].bug_classes
    assert hypotheses[0].target_kind == "endpoint"


def test_endpoint_with_numeric_id_query_param_generates_idor_hypothesis() -> None:
    endpoint = Endpoint(
        value="/product?productId=1", pattern_name="html_link", source_url="https://e.com/"
    )
    hypotheses = generate_hypotheses(_result(endpoints=[endpoint]))

    assert len(hypotheses) == 1
    assert "IDOR" in hypotheses[0].bug_classes


def test_endpoint_with_non_id_query_param_does_not_false_positive() -> None:
    # "valid" and "void" both contain "id" as a raw substring but must not match.
    endpoint = Endpoint(
        value="/search?valid=1&void=2", pattern_name="html_link", source_url="https://e.com/"
    )
    assert generate_hypotheses(_result(endpoints=[endpoint])) == []


def test_endpoint_with_webhook_param_generates_ssrf_hypothesis() -> None:
    endpoint = Endpoint(
        value="/api/notify?webhook=http://internal", pattern_name="rest_api_path", source_url="x"
    )
    hypotheses = generate_hypotheses(_result(endpoints=[endpoint]))
    assert len(hypotheses) == 1
    assert "SSRF" in hypotheses[0].bug_classes


def test_endpoint_with_target_url_param_generates_ssrf_hypothesis() -> None:
    endpoint = Endpoint(
        value="/api/fetch?targetUrl=http://x", pattern_name="rest_api_path", source_url="x"
    )
    hypotheses = generate_hypotheses(_result(endpoints=[endpoint]))
    assert "SSRF" in hypotheses[0].bug_classes


def test_endpoint_with_plain_display_url_param_does_not_false_positive_ssrf() -> None:
    # "profileUrl"/"avatarUrl" are common, ordinary display-link params —
    # must not be flagged as SSRF just for containing "url".
    endpoint = Endpoint(
        value="/api/user?profileUrl=http://x", pattern_name="rest_api_path", source_url="x"
    )
    assert generate_hypotheses(_result(endpoints=[endpoint])) == []


def test_endpoint_with_route_parameter_pattern_generates_idor_hypothesis() -> None:
    endpoint = Endpoint(
        value="/dashboard/:userId", pattern_name="express_style_param", source_url="https://e.com"
    )
    hypotheses = generate_hypotheses(_result(endpoints=[endpoint]))
    assert "IDOR" in hypotheses[0].bug_classes


def test_endpoint_with_admin_path_generates_bac_hypothesis() -> None:
    endpoint = Endpoint(
        value="/api/admin/deleteUser", pattern_name="rest_api_path", source_url="https://e.com"
    )
    hypotheses = generate_hypotheses(_result(endpoints=[endpoint]))
    assert "Broken Function-Level Authorization" in hypotheses[0].bug_classes


def test_boring_endpoint_generates_no_hypothesis() -> None:
    endpoint = Endpoint(
        value="/api/v1/health", pattern_name="rest_api_path", source_url="https://e.com"
    )
    hypotheses = generate_hypotheses(_result(endpoints=[endpoint]))
    assert hypotheses == []


def test_matching_ai_verdict_merges_bug_classes_and_uses_ai_test_plan() -> None:
    endpoint = Endpoint(
        value="/api/v1/users/123", pattern_name="rest_api_path", source_url="https://e.com/app.js"
    )
    eid = endpoint_id(endpoint)
    verdict = AIEndpointVerdict(
        evidence_id=eid,
        endpoint_value=endpoint.value,
        source_url=endpoint.source_url,
        bug_classes=["Information Disclosure"],
        priority="high",
        test_plan="Compare responses across two distinct authenticated sessions.",
        confidence=0.8,
        prompt_version="endpoint-intel-v1",
        model="claude-fake-1",
    )
    hypotheses = generate_hypotheses(_result(endpoints=[endpoint], ai_verdicts=[verdict]))

    assert len(hypotheses) == 1
    h = hypotheses[0]
    assert "IDOR" in h.bug_classes
    assert "Information Disclosure" in h.bug_classes
    assert h.proposed_test == verdict.test_plan
    assert any("AI classified" in reason for reason in h.evidence_chain)


def test_js_body_only_endpoint_gets_higher_confidence_and_evidence_note() -> None:
    endpoint = Endpoint(
        value="/api/v1/users/123", pattern_name="rest_api_path", source_url="https://e.com/app.js"
    )
    discrepancy = SchemaDiscrepancy(js_body_only=["/api/v1/users/123"])

    with_body = generate_hypotheses(
        _result(endpoints=[endpoint], endpoint_schema_discrepancy=discrepancy)
    )[0]
    without_body = generate_hypotheses(_result(endpoints=[endpoint]))[0]

    assert with_body.confidence > without_body.confidence
    assert any("Only visible after downloading" in r for r in with_body.evidence_chain)


def test_auth_only_endpoint_gets_higher_confidence_and_evidence_note() -> None:
    endpoint = Endpoint(
        value="/api/v1/users/123",
        pattern_name="rest_api_path",
        source_url="https://e.com/admin.js",
    )

    with_auth = generate_hypotheses(
        _result(endpoints=[endpoint], auth_only_js_urls=["https://e.com/admin.js"])
    )[0]
    without_auth = generate_hypotheses(_result(endpoints=[endpoint]))[0]

    assert with_auth.confidence > without_auth.confidence
    assert any("authenticated session" in r for r in with_auth.evidence_chain)


def test_historically_seen_endpoint_gets_higher_confidence_and_evidence_note() -> None:
    endpoint = Endpoint(
        value="/api/v1/users/123", pattern_name="rest_api_path", source_url="https://e.com/app.js"
    )

    with_history = generate_hypotheses(
        _result(endpoints=[endpoint], historical_endpoint_values=["/api/v1/users/123"])
    )[0]
    without_history = generate_hypotheses(_result(endpoints=[endpoint]))[0]

    assert with_history.confidence > without_history.confidence
    assert any("previous scan" in r for r in with_history.evidence_chain)


def test_secret_always_generates_hypothesis_with_matching_risk() -> None:
    secret = Secret(
        secret_type="aws_access_key",
        severity="critical",
        redacted_value="AKIA****MNOP",
        partial_hash="abc123",
        source_url="https://e.com/app.js",
    )
    hypotheses = generate_hypotheses(_result(secrets=[secret]))

    assert len(hypotheses) == 1
    assert hypotheses[0].target_kind == "secret"
    assert hypotheses[0].risk == "critical"
    assert hypotheses[0].target_value == "AKIA****MNOP"  # never the raw value


def test_dom_finding_always_generates_hypothesis() -> None:
    finding = DomFinding(
        sink_pattern="inner_html",
        sink_value=".innerHTML =",
        co_occurring_sources=["location_hash"],
        source_url="https://e.com/app.js",
    )
    hypotheses = generate_hypotheses(_result(dom_findings=[finding]))
    assert len(hypotheses) == 1
    assert hypotheses[0].bug_classes == ["DOM XSS"]


def test_lodash_merge_sink_generates_prototype_pollution_not_dom_xss() -> None:
    finding = DomFinding(
        sink_pattern="lodash_merge",
        sink_value="_.merge(",
        co_occurring_sources=["location_search"],
        source_url="https://e.com/app.js",
    )
    hypotheses = generate_hypotheses(_result(dom_findings=[finding]))
    assert len(hypotheses) == 1
    assert hypotheses[0].bug_classes == ["Prototype Pollution"]
    assert "__proto__" in hypotheses[0].proposed_test


def test_jquery_extend_deep_sink_generates_prototype_pollution() -> None:
    finding = DomFinding(
        sink_pattern="jquery_extend_deep",
        sink_value="$.extend(true,",
        co_occurring_sources=["post_message_data"],
        source_url="https://e.com/app.js",
    )
    hypotheses = generate_hypotheses(_result(dom_findings=[finding]))
    assert hypotheses[0].bug_classes == ["Prototype Pollution"]


def test_jwt_alg_none_secret_generates_authentication_bypass_hypothesis() -> None:
    secret = Secret(
        secret_type="jwt_alg_none",
        severity="critical",
        redacted_value="eyJh****MQ.",
        partial_hash="abc123",
        source_url="https://e.com/app.js",
    )
    hypotheses = generate_hypotheses(_result(secrets=[secret]))
    assert len(hypotheses) == 1
    assert hypotheses[0].bug_classes == ["Authentication Bypass"]
    assert hypotheses[0].risk == "critical"


def test_firebase_config_secret_generates_misconfigured_database_hypothesis() -> None:
    secret = Secret(
        secret_type="firebase_config",
        severity="medium",
        redacted_value="myap****io.com",
        partial_hash="abc123",
        source_url="https://e.com/app.js",
    )
    hypotheses = generate_hypotheses(_result(secrets=[secret]))
    assert hypotheses[0].bug_classes == ["Misconfigured Cloud Database"]
    assert "/.json" in hypotheses[0].proposed_test


def test_out_of_scope_subdomain_generates_hypothesis_in_scope_does_not() -> None:
    out_of_scope = SubdomainFinding(
        domain="internal-api.example.com",
        source_url="https://e.com/app.js",
        in_scope=False,
        note="discovered, flagged for manual review",
    )
    in_scope = SubdomainFinding(
        domain="api.example.com",
        source_url="https://e.com/app.js",
        in_scope=True,
        note="in scope",
    )
    hypotheses = generate_hypotheses(_result(subdomains=[out_of_scope, in_scope]))

    assert len(hypotheses) == 1
    assert hypotheses[0].target_value == "internal-api.example.com"
    assert hypotheses[0].bug_classes == ["Scope Verification Needed"]


def test_cors_misconfiguration_always_generates_high_risk_hypothesis() -> None:
    cors = CorsMisconfiguration(
        source_url="https://api.e.com/me", allow_origin="*", allow_credentials=True
    )
    hypotheses = generate_hypotheses(_result(cors_findings=[cors]))
    assert len(hypotheses) == 1
    assert hypotheses[0].bug_classes == ["CORS Misconfiguration"]
    assert hypotheses[0].risk == "high"


def test_third_party_script_always_generates_low_risk_hypothesis() -> None:
    script = ThirdPartyScript(
        hostname="cdn.jsdelivr.net",
        script_url="https://cdn.jsdelivr.net/npm/lib@1.0.0/lib.js",
        page_url="https://e.com/",
    )
    hypotheses = generate_hypotheses(_result(third_party_scripts=[script]))
    assert len(hypotheses) == 1
    assert hypotheses[0].bug_classes == ["Client-Side Supply Chain Surface"]
    assert hypotheses[0].risk == "low"


def test_hypothesis_ids_are_stable_and_unique_across_target_kinds() -> None:
    endpoint = Endpoint(
        value="/api/v1/users/123", pattern_name="rest_api_path", source_url="https://e.com"
    )
    secret = Secret(
        secret_type="aws_access_key",
        severity="critical",
        redacted_value="AKIA****MNOP",
        partial_hash="abc123",
        source_url="https://e.com",
    )
    hypotheses = generate_hypotheses(_result(endpoints=[endpoint], secrets=[secret]))
    ids = [h.id for h in hypotheses]
    assert len(ids) == len(set(ids))
