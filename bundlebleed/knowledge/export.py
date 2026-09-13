from __future__ import annotations

import json
from pathlib import Path

import networkx as nx
from networkx.readwrite import json_graph


def write_graph_export(graph: nx.MultiDiGraph, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "graph.json"
    data = json_graph.node_link_data(graph, edges="edges")
    path.write_text(json.dumps(data, indent=2, sort_keys=True, default=str) + "\n")
    return path
