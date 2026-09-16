from __future__ import annotations

from datetime import datetime

from bundlebleed.hypotheses.engine import generate_hypotheses
from bundlebleed.identity import endpoint_id
from bundlebleed.models import (
    AIEndpointVerdict,
    CorsMisconfiguration,
    DanglingCnameFinding,
    DomFinding,
    Endpoint,
    GraphQLOperation,
    MassAssignmentFinding,
    PostMessageFinding,
    ScanResult,
    SchemaDiscrepancy,
    Secret,
    SubdomainFinding,
    ThirdPartyScript,
    VulnerableLibraryFinding,
    WebSocketFinding,
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


def test_location_href_assign_sink_generates_open_redirect_not_dom_xss() -> None:
    finding = DomFinding(
        sink_pattern="location_href_assign",
        sink_value="location.href =",
        co_occurring_sources=["location_search"],
        source_url="https://e.com/app.js",
    )
    hypotheses = generate_hypotheses(_result(dom_findings=[finding]))
    assert len(hypotheses) == 1
    assert hypotheses[0].bug_classes == ["Open Redirect"]
    assert "redirect_uri" in hypotheses[0].proposed_test


def test_window_open_sink_generates_open_redirect() -> None:
    finding = DomFinding(
        sink_pattern="window_open",
        sink_value="window.open(",
        co_occurring_sources=["location_hash"],
        source_url="https://e.com/app.js",
    )
    hypotheses = generate_hypotheses(_result(dom_findings=[finding]))
    assert hypotheses[0].bug_classes == ["Open Redirect"]


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


def test_graphql_introspection_reference_generates_expected_hypothesis() -> None:
    secret = Secret(
        secret_type="graphql_introspection_reference",
        severity="medium",
        redacted_value="Intr****uery",
        partial_hash="abc123",
        source_url="https://e.com/app.js",
    )
    hypotheses = generate_hypotheses(_result(secrets=[secret]))
    assert hypotheses[0].bug_classes == ["GraphQL Introspection Exposure"]
    assert "__schema" in hypotheses[0].proposed_test


def test_cloud_storage_reference_generates_takeover_candidate_hypothesis() -> None:
    secret = Secret(
        secret_type="cloud_storage_reference",
        severity="medium",
        redacted_value="myap****.com",
        partial_hash="abc123",
        source_url="https://e.com/app.js",
    )
    hypotheses = generate_hypotheses(_result(secrets=[secret]))
    assert hypotheses[0].bug_classes == ["Possible Subdomain/Bucket Takeover Candidate"]


def test_cloud_metadata_reference_generates_ssrf_target_hypothesis() -> None:
    secret = Secret(
        secret_type="cloud_metadata_reference",
        severity="critical",
        redacted_value="169.****.254",
        partial_hash="abc123",
        source_url="https://e.com/app.js",
    )
    hypotheses = generate_hypotheses(_result(secrets=[secret]))
    assert hypotheses[0].bug_classes == ["Cloud Metadata Endpoint Reference (possible SSRF target)"]
    assert hypotheses[0].risk == "critical"


def test_exposed_api_docs_path_generates_expected_hypothesis() -> None:
    secret = Secret(
        secret_type="exposed_api_docs_path",
        severity="medium",
        redacted_value="/swa****son",
        partial_hash="abc123",
        source_url="https://e.com/app.js",
    )
    hypotheses = generate_hypotheses(_result(secrets=[secret]))
    assert hypotheses[0].bug_classes == ["Exposed API Documentation"]


def test_exposed_vcs_config_path_generates_expected_hypothesis() -> None:
    secret = Secret(
        secret_type="exposed_vcs_config_path",
        severity="high",
        redacted_value="/.gi****nfig",
        partial_hash="abc123",
        source_url="https://e.com/app.js",
    )
    hypotheses = generate_hypotheses(_result(secrets=[secret]))
    assert hypotheses[0].bug_classes == ["Exposed VCS/Config Path Reference"]
    assert hypotheses[0].risk == "high"


def test_internal_hostname_reference_generates_disclosure_hypothesis() -> None:
    secret = Secret(
        secret_type="internal_hostname_reference",
        severity="low",
        redacted_value="stag****.com",
        partial_hash="abc123",
        source_url="https://e.com/app.js",
    )
    hypotheses = generate_hypotheses(_result(secrets=[secret]))
    assert hypotheses[0].bug_classes == ["Internal Hostname Disclosure"]
    assert hypotheses[0].risk == "low"


def test_generic_credential_secret_falls_back_to_hardcoded_credential_exposure() -> None:
    secret = Secret(
        secret_type="openai_api_key",
        severity="critical",
        redacted_value="sk-a****dEfg",
        partial_hash="abc123",
        source_url="https://e.com/app.js",
    )
    hypotheses = generate_hypotheses(_result(secrets=[secret]))
    assert hypotheses[0].bug_classes == ["Hardcoded Credential Exposure"]
    # openai_api_key has a concrete KeyHacks command drafted for the human
    # to run themselves -- this tool never sends it.
    assert "api.openai.com/v1/models" in hypotheses[0].proposed_test
    assert "this tool never validates a credential itself" in hypotheses[0].proposed_test.lower()


def test_secret_type_with_no_known_keyhacks_command_gets_generic_guidance() -> None:
    secret = Secret(
        secret_type="hardcoded_password",
        severity="medium",
        redacted_value="pass****word",
        partial_hash="abc123",
        source_url="https://e.com/app.js",
    )
    hypotheses = generate_hypotheses(_result(secrets=[secret]))
    assert hypotheses[0].bug_classes == ["Hardcoded Credential Exposure"]
    assert "KeyHacks method for its type" in hypotheses[0].proposed_test


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


def test_postmessage_finding_generates_high_risk_hypothesis() -> None:
    pm = PostMessageFinding(
        source_url="https://e.com/app.js", snippet_preview="addEventListener('message'"
    )
    hypotheses = generate_hypotheses(_result(postmessage_findings=[pm]))
    assert len(hypotheses) == 1
    assert hypotheses[0].bug_classes == ["PostMessage Missing Origin Check"]
    assert hypotheses[0].risk == "high"


def test_websocket_finding_generates_medium_risk_hypothesis() -> None:
    ws = WebSocketFinding(
        source_url="https://e.com/app.js", snippet_preview="new WebSocket('wss://e.com/socket')"
    )
    hypotheses = generate_hypotheses(_result(websocket_findings=[ws]))
    assert len(hypotheses) == 1
    assert hypotheses[0].bug_classes == ["Cross-Site WebSocket Hijacking Candidate"]
    assert hypotheses[0].risk == "medium"


def test_mass_assignment_finding_preserves_its_severity_as_risk() -> None:
    high = MassAssignmentFinding(
        source_url="https://e.com/app.js", field_name="role", severity="high", snippet_preview="x"
    )
    medium = MassAssignmentFinding(
        source_url="https://e.com/app.js",
        field_name="verified",
        severity="medium",
        snippet_preview="x",
    )
    hypotheses = generate_hypotheses(_result(mass_assignment_findings=[high, medium]))
    assert len(hypotheses) == 2
    by_field = {h.target_value: h for h in hypotheses}
    assert by_field["role"].bug_classes == ["Mass Assignment / Object Property Injection"]
    assert by_field["role"].risk == "high"
    assert by_field["verified"].risk == "medium"


def test_vulnerable_library_finding_generates_expected_hypothesis() -> None:
    lib = VulnerableLibraryFinding(
        source_url="https://e.com/vendor.js",
        library_name="jquery",
        detected_version="3.4.1",
        vulnerable_below="3.5.0",
        cve="CVE-2020-11022",
        severity="high",
        description="jQuery XSS via .html()",
    )
    hypotheses = generate_hypotheses(_result(vulnerable_libraries=[lib]))
    assert len(hypotheses) == 1
    assert hypotheses[0].bug_classes == ["Known-Vulnerable JS Dependency"]
    assert hypotheses[0].risk == "high"
    assert "CVE-2020-11022" in hypotheses[0].evidence_chain[1]


def test_sensitive_named_mutation_generates_high_risk_hypothesis() -> None:
    op = GraphQLOperation(
        operation_type="mutation", operation_name="DeleteUser", source_url="https://e.com/app.js"
    )
    hypotheses = generate_hypotheses(_result(graphql_operations=[op]))
    assert len(hypotheses) == 1
    assert hypotheses[0].bug_classes == ["GraphQL Mutation Exposed"]
    assert hypotheses[0].risk == "high"


def test_non_sensitive_named_mutation_generates_medium_risk_hypothesis() -> None:
    op = GraphQLOperation(
        operation_type="mutation", operation_name="UpdateProfile", source_url="https://e.com/app.js"
    )
    hypotheses = generate_hypotheses(_result(graphql_operations=[op]))
    assert len(hypotheses) == 1
    assert hypotheses[0].risk == "medium"


def test_graphql_query_does_not_generate_a_hypothesis() -> None:
    op = GraphQLOperation(
        operation_type="query", operation_name="GetUser", source_url="https://e.com/app.js"
    )
    hypotheses = generate_hypotheses(_result(graphql_operations=[op]))
    assert hypotheses == []


def test_dangling_cname_generates_high_risk_takeover_candidate() -> None:
    cname = DanglingCnameFinding(
        domain="blog.e.com",
        cname_target="some-unclaimed-app.herokuapp.com",
        service_hint="herokuapp.com",
    )
    hypotheses = generate_hypotheses(_result(dangling_cnames=[cname]))
    assert len(hypotheses) == 1
    assert hypotheses[0].bug_classes == ["Subdomain Takeover Candidate"]
    assert hypotheses[0].risk == "high"
    assert "never contacted the CNAME target" in hypotheses[0].evidence_chain[1]


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
