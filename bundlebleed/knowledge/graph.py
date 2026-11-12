from __future__ import annotations

import networkx as nx

from bundlebleed.models import GraphStats, ScanResult


def _source_node(url: str) -> str:
    return f"source:{url}"


def build_graph(result: ScanResult) -> nx.MultiDiGraph:
    """Turn a flat ScanResult into an entity-relationship graph: every
    source URL is a node (kind "bundle" if its body was downloaded, else
    "url"), every finding extracted from it is a node, and a "contains"
    (or "references", for subdomains) edge connects the two.

    Node IDs are built from the same fields `ScanResult.normalized()`
    dedups on, so two scans of the same fixtures/target produce an
    identical graph.
    """
    graph: nx.MultiDiGraph = nx.MultiDiGraph()
    r = result.normalized()

    file_urls = {f.url for f in r.files}
    sources = file_urls.copy()
    sources |= {e.source_url for e in r.endpoints}
    sources |= {s.source_url for s in r.secrets}
    sources |= {s.source_url for s in r.subdomains}
    sources |= {p.source_url for p in r.parameters}
    sources |= {d.source_url for d in r.dom_findings}

    for url in sorted(sources):
        graph.add_node(_source_node(url), kind="bundle" if url in file_urls else "url", url=url)

    for e in r.endpoints:
        node_id = f"endpoint:{e.pattern_name}:{e.value}:{e.source_url}"
        graph.add_node(node_id, kind="endpoint", value=e.value, pattern_name=e.pattern_name)
        graph.add_edge(_source_node(e.source_url), node_id, relation="contains")

    for s in r.secrets:
        node_id = f"secret:{s.secret_type}:{s.partial_hash}:{s.source_url}"
        graph.add_node(node_id, kind="secret", secret_type=s.secret_type, severity=s.severity)
        graph.add_edge(_source_node(s.source_url), node_id, relation="contains")

    for sd in r.subdomains:
        node_id = f"subdomain:{sd.domain}:{sd.source_url}"
        graph.add_node(node_id, kind="subdomain", domain=sd.domain, in_scope=sd.in_scope)
        graph.add_edge(_source_node(sd.source_url), node_id, relation="references")

    for p in r.parameters:
        node_id = f"parameter:{p.name}:{p.source_url}"
        graph.add_node(node_id, kind="parameter", name=p.name)
        graph.add_edge(_source_node(p.source_url), node_id, relation="contains")

    for d in r.dom_findings:
        node_id = f"dom_finding:{d.sink_pattern}:{d.source_url}"
        graph.add_node(node_id, kind="dom_finding", sink_pattern=d.sink_pattern)
        graph.add_edge(_source_node(d.source_url), node_id, relation="contains")

    return graph


def graph_stats(graph: nx.MultiDiGraph) -> GraphStats:
    bundle_count = sum(1 for _, kind in graph.nodes(data="kind") if kind == "bundle")
    return GraphStats(
        node_count=graph.number_of_nodes(),
        edge_count=graph.number_of_edges(),
        bundle_count=bundle_count,
    )
