from __future__ import annotations

from datetime import datetime

from bundlebleed.models import Endpoint, ObjectAccessCandidateRef, ScanResult
from bundlebleed.reporters.curls import render_curls_sh


def _base(**kwargs) -> ScanResult:
    return ScanResult(scan_run_id="run-1", started_at=datetime.now(), **kwargs)  # type: ignore[arg-type]


def _ep(value: str, tag: str = "live") -> Endpoint:
    return Endpoint(value=value, pattern_name="url_path", source_url="https://example.com/app.js", tag=tag)  # type: ignore[arg-type]


def test_header_present() -> None:
    rendered = render_curls_sh(_base())
    assert "BUNDLEBLEED_COOKIE" in rendered
    assert "BUNDLEBLEED_BASE" in rendered
    assert "MANUAL FIRING REQUIRED" in rendered


def test_bola_candidate_included() -> None:
    result = _base(
        endpoints=[_ep("/api/v1/invoices/:invoiceId")],
        object_access_candidates=[
            ObjectAccessCandidateRef(
                endpoint="/api/v1/invoices/:invoiceId",
                identifier="invoiceId",
                function_name=None,
                level=1,
                bug_class="BOLA",
                source_url="https://example.com/app.js",
            )
        ],
    )
    rendered = render_curls_sh(result)
    assert "BOLA" in rendered
    assert "REPLACE_ID" in rendered


def test_bfla_candidate_included() -> None:
    result = _base(
        object_access_candidates=[
            ObjectAccessCandidateRef(
                endpoint="/api/admin/users",
                identifier="privileged_path",
                function_name=None,
                level=2,
                bug_class="BFLA",
                source_url="https://example.com/app.js",
            )
        ],
    )
    rendered = render_curls_sh(result)
    assert "BFLA" in rendered
    assert "/api/admin/users" in rendered


def test_auth_required_endpoints_included() -> None:
    result = _base(endpoints=[_ep("/api/profile", tag="auth-required")])
    rendered = render_curls_sh(result)
    assert "auth-required" in rendered.lower() or "/api/profile" in rendered


def test_unauthed_endpoints_included() -> None:
    result = _base(endpoints=[_ep("/api/public/data", tag="unauthed")])
    rendered = render_curls_sh(result)
    assert "/api/public/data" in rendered


def test_graphql_introspection_included() -> None:
    from bundlebleed.models import GraphQLOperationRef
    result = _base(
        graphql_operations=[
            GraphQLOperationRef(
                op_type="query",
                op_name="GetUser",
                endpoint="/graphql",
                file="app.js",
                line=1,
                source_url="https://example.com/app.js",
            )
        ]
    )
    rendered = render_curls_sh(result)
    assert "__schema" in rendered or "introspection" in rendered.lower()


def test_parameterized_path_replaced() -> None:
    result = _base(
        object_access_candidates=[
            ObjectAccessCandidateRef(
                endpoint="/api/users/:userId",
                identifier="userId",
                function_name=None,
                level=1,
                bug_class="BOLA",
                source_url="https://example.com/app.js",
            )
        ]
    )
    rendered = render_curls_sh(result)
    assert ":userId" not in rendered
    assert "REPLACE_ID" in rendered


def test_empty_result_still_renders_header() -> None:
    rendered = render_curls_sh(_base())
    assert "_curl()" in rendered or "curl" in rendered
