from __future__ import annotations

from datetime import datetime

from bundlebleed.models import (
    AuthFindingRef,
    DomTaintFindingRef,
    EntropySecret,
    GraphQLOperationRef,
    InterestingComment,
    ObjectAccessCandidateRef,
    PostMessageFindingRef,
    ProtoPollutionFindingRef,
    ScanResult,
    WebSocketFindingRef,
    WorkerFindingRef,
)
from bundlebleed.reporters.markdown_report import render_markdown


def _base(**kwargs) -> ScanResult:
    return ScanResult(scan_run_id="run-1", started_at=datetime.now(), **kwargs)  # type: ignore[arg-type]


def test_entropy_secrets_section_present() -> None:
    rendered = render_markdown(_base())
    assert "## Entropy secrets" in rendered


def test_entropy_secret_rendered() -> None:
    result = _base(
        entropy_secrets=[
            EntropySecret(
                file="app.js", line=5, entropy_score=4.9,
                redacted_value="rPmX...XXX", partial_hash="aabb1122",
                source_url="https://example.com/app.js",
            )
        ]
    )
    rendered = render_markdown(result)
    assert "4.9" in rendered or "4.90" in rendered
    assert "rPmX...XXX" in rendered


def test_interesting_comments_section() -> None:
    result = _base(
        interesting_comments=[
            InterestingComment(
                text="// TODO: remove debug endpoint",
                file="app.js", line=12,
                keyword_matched="debug",
                source_url="https://example.com/app.js",
            )
        ]
    )
    rendered = render_markdown(result)
    assert "## Interesting comments" in rendered
    assert "debug" in rendered


def test_graphql_section_rendered() -> None:
    result = _base(
        graphql_operations=[
            GraphQLOperationRef(
                op_type="mutation", op_name="DeleteAccount",
                endpoint="/graphql", variables=["userId"],
                file="app.js", line=1,
                source_url="https://example.com/app.js",
            )
        ]
    )
    rendered = render_markdown(result)
    assert "## GraphQL operations" in rendered
    assert "DeleteAccount" in rendered


def test_websocket_section_rendered() -> None:
    result = _base(
        websocket_findings=[
            WebSocketFindingRef(
                endpoint="wss://api.example.com/ws",
                protocol="websocket",
                auth_in_url=True,
                has_origin_check=False,
                file="app.js", line=5,
                source_url="https://example.com/app.js",
            )
        ]
    )
    rendered = render_markdown(result)
    assert "## WebSocket findings" in rendered
    assert "wss://api.example.com/ws" in rendered


def test_auth_findings_section_rendered() -> None:
    result = _base(
        auth_findings=[
            AuthFindingRef(
                finding_type="jwt_alg_none",
                detail="alg: none",
                severity_candidate="critical",
                file="app.js", line=3,
                source_url="https://example.com/app.js",
            )
        ]
    )
    rendered = render_markdown(result)
    assert "## Auth configuration findings" in rendered
    assert "jwt_alg_none" in rendered
    assert "critical" in rendered


def test_object_access_candidates_section() -> None:
    result = _base(
        object_access_candidates=[
            ObjectAccessCandidateRef(
                endpoint="/api/invoices/:invoiceId",
                identifier="invoiceId",
                function_name=None,
                level=1,
                bug_class="BOLA",
                source_url="https://example.com/app.js",
            )
        ]
    )
    rendered = render_markdown(result)
    assert "Access control candidates" in rendered
    assert "BOLA" in rendered


def test_dom_taint_section_rendered() -> None:
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
    rendered = render_markdown(result)
    assert "## DOM taint findings" in rendered
    assert "location.search" in rendered
    assert "innerHTML" in rendered


def test_proto_pollution_section_rendered() -> None:
    result = _base(
        proto_pollution_findings=[
            ProtoPollutionFindingRef(
                level=3, pattern_name="lodash_merge",
                detail="[L3] lodash_merge: `_.merge(target, input)`",
                file="app.js", line=22,
                source_url="https://example.com/app.js",
            )
        ]
    )
    rendered = render_markdown(result)
    assert "## Prototype pollution findings" in rendered
    assert "lodash_merge" in rendered


def test_postmessage_section_rendered() -> None:
    result = _base(
        postmessage_findings=[
            PostMessageFindingRef(
                kind="sender",
                target_origin="*",
                has_origin_check=False,
                data_sinks=[],
                file="app.js", line=7,
                source_url="https://example.com/app.js",
            )
        ]
    )
    rendered = render_markdown(result)
    assert "## postMessage findings" in rendered
    assert "⚠️" in rendered  # wildcard flagged


def test_worker_findings_section_rendered() -> None:
    result = _base(
        worker_findings=[
            WorkerFindingRef(
                worker_type="service_worker",
                worker_url="/sw.js",
                has_fetch_intercept=True,
                is_inline_blob=False,
                file="app.js", line=1,
                source_url="https://example.com/app.js",
            )
        ]
    )
    rendered = render_markdown(result)
    assert "## Worker findings" in rendered
    assert "service_worker" in rendered
    assert "/sw.js" in rendered
