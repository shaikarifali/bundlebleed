from __future__ import annotations

from datetime import datetime

from bundlebleed.hypotheses.engine import generate_hypotheses
from bundlebleed.models import (
    AuthFindingRef,
    DomTaintFindingRef,
    PostMessageFindingRef,
    ProtoPollutionFindingRef,
    ScanResult,
    WebSocketFindingRef,
)


def _base(**kwargs) -> ScanResult:
    return ScanResult(scan_run_id="run-1", started_at=datetime.now(), **kwargs)  # type: ignore[arg-type]


# --- DOM taint hypotheses ---

def test_dom_taint_xss_hypothesis_generated() -> None:
    result = _base(
        dom_taint_findings=[
            DomTaintFindingRef(
                source_name="location.search",
                source_line=5,
                sink_name="innerHTML",
                sink_line=8,
                sink_category="xss",
                file="app.js",
                source_url="https://example.com/app.js",
            )
        ]
    )
    hyps = generate_hypotheses(result)
    dom_hyps = [h for h in hyps if h.target_kind == "dom_taint"]
    assert len(dom_hyps) == 1
    assert "DOM XSS" in dom_hyps[0].bug_classes[0]
    assert "location.search" in dom_hyps[0].target_value
    assert "innerHTML" in dom_hyps[0].target_value


def test_dom_taint_open_redirect_hypothesis() -> None:
    result = _base(
        dom_taint_findings=[
            DomTaintFindingRef(
                source_name="location.hash",
                source_line=1,
                sink_name="location.href_assign",
                sink_line=3,
                sink_category="open_redirect",
                file="app.js",
                source_url="https://example.com/app.js",
            )
        ]
    )
    hyps = generate_hypotheses(result)
    dom_hyps = [h for h in hyps if h.target_kind == "dom_taint"]
    assert len(dom_hyps) == 1
    assert dom_hyps[0].bug_classes == ["Open Redirect"]
    assert dom_hyps[0].risk == "medium"


def test_dom_taint_code_exec_hypothesis() -> None:
    result = _base(
        dom_taint_findings=[
            DomTaintFindingRef(
                source_name="event.data",
                source_line=2,
                sink_name="eval",
                sink_line=4,
                sink_category="code_exec",
                file="app.js",
                source_url="https://example.com/app.js",
            )
        ]
    )
    hyps = generate_hypotheses(result)
    dom_hyps = [h for h in hyps if h.target_kind == "dom_taint"]
    assert "Code Execution" in dom_hyps[0].bug_classes[0]
    assert dom_hyps[0].risk == "high"


def test_dom_taint_duplicate_deduped() -> None:
    finding = DomTaintFindingRef(
        source_name="location.search", source_line=5, sink_name="innerHTML",
        sink_line=8, sink_category="xss", file="app.js",
        source_url="https://example.com/app.js",
    )
    result = _base(dom_taint_findings=[finding, finding])
    dom_hyps = [h for h in generate_hypotheses(result) if h.target_kind == "dom_taint"]
    assert len(dom_hyps) == 1


# --- Prototype pollution hypotheses ---

def test_proto_pollution_l1_hypothesis() -> None:
    result = _base(
        proto_pollution_findings=[
            ProtoPollutionFindingRef(
                level=1,
                pattern_name="proto_direct_bracket",
                detail="[L1] direct __proto__ write",
                file="app.js",
                line=10,
                source_url="https://example.com/app.js",
            )
        ]
    )
    hyps = generate_hypotheses(result)
    pp_hyps = [h for h in hyps if h.target_kind == "proto_pollution"]
    assert len(pp_hyps) == 1
    assert pp_hyps[0].bug_classes == ["Prototype Pollution"]


def test_proto_pollution_l5_higher_confidence() -> None:
    result = _base(
        proto_pollution_findings=[
            ProtoPollutionFindingRef(
                level=5, pattern_name="object_prototype_direct",
                detail="[L5] Object.prototype direct mutation",
                file="app.js", line=20,
                source_url="https://example.com/app.js",
            )
        ]
    )
    result_l1 = _base(
        proto_pollution_findings=[
            ProtoPollutionFindingRef(
                level=1, pattern_name="proto_direct_bracket",
                detail="[L1] direct __proto__ write",
                file="app.js", line=10,
                source_url="https://example.com/app.js",
            )
        ]
    )
    hyps_l5 = [h for h in generate_hypotheses(result) if h.target_kind == "proto_pollution"]
    hyps_l1 = [h for h in generate_hypotheses(result_l1) if h.target_kind == "proto_pollution"]
    assert hyps_l5[0].confidence > hyps_l1[0].confidence


def test_proto_pollution_l3_risk_high() -> None:
    result = _base(
        proto_pollution_findings=[
            ProtoPollutionFindingRef(
                level=3, pattern_name="lodash_merge",
                detail="[L3] lodash_merge", file="app.js", line=5,
                source_url="https://example.com/app.js",
            )
        ]
    )
    pp_hyps = [h for h in generate_hypotheses(result) if h.target_kind == "proto_pollution"]
    assert pp_hyps[0].risk == "high"


# --- Auth finding hypotheses ---

def test_jwt_alg_none_hypothesis_critical() -> None:
    result = _base(
        auth_findings=[
            AuthFindingRef(
                finding_type="jwt_alg_none",
                detail="alg: none detected",
                severity_candidate="critical",
                file="app.js", line=3,
                source_url="https://example.com/app.js",
            )
        ]
    )
    hyps = generate_hypotheses(result)
    auth_hyps = [h for h in hyps if h.target_kind == "auth_finding"]
    assert len(auth_hyps) == 1
    assert auth_hyps[0].bug_classes == ["Authentication Bypass"]
    assert auth_hyps[0].risk == "critical"
    assert auth_hyps[0].confidence > 0.5


def test_oauth_missing_pkce_hypothesis() -> None:
    result = _base(
        auth_findings=[
            AuthFindingRef(
                finding_type="oauth_missing_pkce",
                detail="PKCE not found",
                severity_candidate="medium",
                file="app.js", line=7,
                source_url="https://example.com/app.js",
            )
        ]
    )
    auth_hyps = [h for h in generate_hypotheses(result) if h.target_kind == "auth_finding"]
    assert len(auth_hyps) == 1
    assert "OAuth" in auth_hyps[0].bug_classes[0] or "Code" in auth_hyps[0].bug_classes[0]


def test_unknown_auth_finding_type_skipped() -> None:
    result = _base(
        auth_findings=[
            AuthFindingRef(
                finding_type="unknown_exotic_pattern",
                detail="something",
                severity_candidate="low",
                file="app.js", line=1,
                source_url="https://example.com/app.js",
            )
        ]
    )
    auth_hyps = [h for h in generate_hypotheses(result) if h.target_kind == "auth_finding"]
    assert auth_hyps == []


# --- postMessage hypotheses ---

def test_postmessage_wildcard_sender_hypothesis() -> None:
    result = _base(
        postmessage_findings=[
            PostMessageFindingRef(
                kind="sender", target_origin="*", has_origin_check=False,
                data_sinks=[], file="app.js", line=5,
                source_url="https://example.com/app.js",
            )
        ]
    )
    pm_hyps = [h for h in generate_hypotheses(result) if h.target_kind == "postmessage"]
    assert len(pm_hyps) == 1
    assert "postMessage Data Exposure" in pm_hyps[0].bug_classes


def test_postmessage_receiver_no_origin_check_hypothesis() -> None:
    result = _base(
        postmessage_findings=[
            PostMessageFindingRef(
                kind="receiver", target_origin=None, has_origin_check=False,
                data_sinks=["innerHTML"], file="app.js", line=12,
                source_url="https://example.com/app.js",
            )
        ]
    )
    pm_hyps = [h for h in generate_hypotheses(result) if h.target_kind == "postmessage"]
    assert len(pm_hyps) == 1
    assert "postMessage Injection" in pm_hyps[0].bug_classes
    assert pm_hyps[0].risk == "high"


def test_postmessage_receiver_with_origin_check_no_hypothesis() -> None:
    result = _base(
        postmessage_findings=[
            PostMessageFindingRef(
                kind="receiver", target_origin=None, has_origin_check=True,
                data_sinks=["innerHTML"], file="app.js", line=12,
                source_url="https://example.com/app.js",
            )
        ]
    )
    pm_hyps = [h for h in generate_hypotheses(result) if h.target_kind == "postmessage"]
    assert pm_hyps == []


def test_postmessage_safe_sender_no_hypothesis() -> None:
    result = _base(
        postmessage_findings=[
            PostMessageFindingRef(
                kind="sender", target_origin="https://trusted.example.com",
                has_origin_check=False, data_sinks=[],
                file="app.js", line=3,
                source_url="https://example.com/app.js",
            )
        ]
    )
    pm_hyps = [h for h in generate_hypotheses(result) if h.target_kind == "postmessage"]
    assert pm_hyps == []


# --- WebSocket hypotheses ---

def test_websocket_auth_in_url_hypothesis() -> None:
    result = _base(
        websocket_findings=[
            WebSocketFindingRef(
                endpoint="wss://api.example.com/ws?token=eyJ...",
                protocol="websocket",
                auth_in_url=True,
                has_origin_check=False,
                file="app.js", line=5,
                source_url="https://example.com/app.js",
            )
        ]
    )
    ws_hyps = [h for h in generate_hypotheses(result) if h.target_kind == "websocket"]
    assert len(ws_hyps) == 1
    assert "WebSocket" in ws_hyps[0].bug_classes[0]
    assert ws_hyps[0].risk == "medium"


def test_websocket_no_auth_in_url_no_hypothesis() -> None:
    result = _base(
        websocket_findings=[
            WebSocketFindingRef(
                endpoint="wss://api.example.com/ws",
                protocol="websocket",
                auth_in_url=False,
                has_origin_check=True,
                file="app.js", line=5,
                source_url="https://example.com/app.js",
            )
        ]
    )
    ws_hyps = [h for h in generate_hypotheses(result) if h.target_kind == "websocket"]
    assert ws_hyps == []
