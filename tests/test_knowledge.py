from __future__ import annotations

import json
from datetime import datetime

from bundlebleed.knowledge.export import write_graph_export
from bundlebleed.knowledge.graph import build_graph, graph_stats
from bundlebleed.knowledge.schema import endpoint_schema_discrepancy
from bundlebleed.models import (
    DomFinding,
    Endpoint,
    FileAnalysis,
    ParameterFinding,
    ScanResult,
    Secret,
    SubdomainFinding,
)


def _sample_result() -> ScanResult:
    return ScanResult(
        scan_run_id="run-1",
        started_at=datetime.now(),
        targets=["example.com"],
        collected_urls=["https://example.com/app.js"],
        files=[FileAnalysis(url="https://example.com/app.js", frameworks=["react"])],
        endpoints=[
            Endpoint(
                value="/api/v1/users/",
                pattern_name="rest_api_path",
                source_url="https://example.com/app.js",
            )
        ],
        secrets=[
            Secret(
                secret_type="aws_access_key",
                severity="critical",
                redacted_value="AKIA****MNOP",
                partial_hash="abc123",
                source_url="https://example.com/app.js",
            )
        ],
        subdomains=[
            SubdomainFinding(
                domain="internal-api.example.com",
                source_url="https://example.com/app.js",
                in_scope=True,
                note="in scope",
            )
        ],
        parameters=[ParameterFinding(name="authToken", source_url="https://example.com/app.js")],
        dom_findings=[
            DomFinding(
                sink_pattern="inner_html",
                sink_value=".innerHTML =",
                co_occurring_sources=["location_hash"],
                source_url="https://example.com/app.js",
            )
        ],
    )


def test_build_graph_creates_one_bundle_node_and_one_node_per_finding() -> None:
    result = _sample_result()
    graph = build_graph(result)

    assert graph.nodes["source:https://example.com/app.js"]["kind"] == "bundle"
    # 1 bundle + 1 endpoint + 1 secret + 1 subdomain + 1 parameter + 1 dom_finding
    assert graph.number_of_nodes() == 6
    # each finding gets exactly one "contains"/"references" edge from the bundle
    assert graph.number_of_edges() == 5


def test_build_graph_uses_url_kind_for_sources_never_downloaded() -> None:
    result = ScanResult(
        scan_run_id="run-1",
        started_at=datetime.now(),
        endpoints=[
            Endpoint(value="/api/x", pattern_name="rest_api_path", source_url="https://e.com/x")
        ],
    )
    graph = build_graph(result)
    assert graph.nodes["source:https://e.com/x"]["kind"] == "url"


def test_graph_stats_counts_bundles_correctly() -> None:
    graph = build_graph(_sample_result())
    stats = graph_stats(graph)
    assert stats.bundle_count == 1
    assert stats.node_count == graph.number_of_nodes()
    assert stats.edge_count == graph.number_of_edges()


def test_build_graph_is_deterministic_across_runs() -> None:
    result = _sample_result()
    graph_a = build_graph(result)
    graph_b = build_graph(result)
    assert sorted(graph_a.nodes) == sorted(graph_b.nodes)
    assert sorted(graph_a.edges) == sorted(graph_b.edges)


def test_endpoint_schema_discrepancy_splits_by_source() -> None:
    url_endpoints = [Endpoint(value="/api/v1/a", pattern_name="p", source_url="u1")]
    body_endpoints = [
        Endpoint(value="/api/v1/a", pattern_name="p", source_url="u1"),
        Endpoint(value="/api/v1/hidden", pattern_name="p", source_url="u1"),
    ]

    discrepancy = endpoint_schema_discrepancy(url_endpoints, body_endpoints)

    assert discrepancy.both == ["/api/v1/a"]
    assert discrepancy.js_body_only == ["/api/v1/hidden"]
    assert discrepancy.url_only == []


def test_write_graph_export_produces_valid_node_link_json(tmp_path) -> None:  # type: ignore[no-untyped-def]
    graph = build_graph(_sample_result())
    path = write_graph_export(graph, tmp_path)

    data = json.loads(path.read_text())
    assert len(data["nodes"]) == graph.number_of_nodes()
    assert len(data["edges"]) == graph.number_of_edges()
