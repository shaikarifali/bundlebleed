from __future__ import annotations

import json
import re

from pydantic import BaseModel, Field


class AssetGraphNode(BaseModel):
    """A JS chunk or bundle node in the asset dependency graph."""

    chunk_name: str | None   # webpack chunk name, vite entry key, or next chunk id
    chunk_url: str           # URL path of the chunk (may be relative)
    bundler: str             # "webpack" | "vite" | "next" | "unknown"
    static_imports: list[str] = Field(default_factory=list)
    dynamic_imports: list[str] = Field(default_factory=list)
    source_url: str          # JS file this node was extracted from


class AssetGraph(BaseModel):
    """Full asset dependency graph derived from JS manifests and imports."""

    nodes: list[AssetGraphNode] = Field(default_factory=list)
    bundler: str             # dominant bundler detected
    total_chunks: int
    has_dynamic_imports: bool
    entry_points: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Bundler detection
# ---------------------------------------------------------------------------

_WEBPACK_SIGNALS = [
    re.compile(r"""\b__webpack_require__\b"""),
    re.compile(r"""\bwebpackChunk[A-Za-z_$]"""),
    re.compile(r"""\bwebpackJsonp\b"""),
    re.compile(r"""webpackChunkName\s*:"""),
]
_VITE_SIGNALS = [
    re.compile(r"""\b_?_vitePreload\b"""),
    re.compile(r"""\b__vite__mapDeps\b"""),
    re.compile(r"""/@vite/"""),
]
_NEXT_SIGNALS = [
    re.compile(r"""\b__NEXT_DATA__\b"""),
    re.compile(r"""/_next/static/"""),
    re.compile(r"""\bnextChunksUrl\b"""),
    re.compile(r"""\bbuildManifest\b"""),
]


def _detect_bundler(content: str) -> str:
    scores = {
        "webpack": sum(1 for p in _WEBPACK_SIGNALS if p.search(content)),
        "vite": sum(1 for p in _VITE_SIGNALS if p.search(content)),
        "next": sum(1 for p in _NEXT_SIGNALS if p.search(content)),
    }
    best = max(scores, key=scores.__getitem__)
    return best if scores[best] > 0 else "unknown"


# ---------------------------------------------------------------------------
# Chunk / import extraction patterns
# ---------------------------------------------------------------------------

# webpack chunk name comment: /* webpackChunkName: "name" */
_WEBPACK_CHUNK_NAME_RE = re.compile(
    r"""/\*\s*webpackChunkName\s*:\s*['"`]([^'"`]+)['"`]\s*\*/""",
    re.IGNORECASE,
)

# dynamic import() — both quoted and chunk-comment variants
_DYNAMIC_IMPORT_RE = re.compile(
    r"""import\s*\(\s*(?:/\*[^*]*\*/\s*)?['"`]([^'"`]+)['"`]\s*\)""",
)

# static import ... from '...'
_STATIC_IMPORT_RE = re.compile(
    r"""(?:^|;)\s*import\s+(?:[^'"`;]*)?\s*from\s+['"`]([^'"`]+)['"`]""",
    re.MULTILINE,
)

# Next.js: /_next/static/chunks/<name>.js
_NEXT_CHUNK_URL_RE = re.compile(r"""/_next/static/chunks/([^'")\s,]+\.js)""")

# webpack require.ensure / require([...])
_WEBPACK_ENSURE_RE = re.compile(
    r"""require\.ensure\s*\(\s*\[([^\]]*)\]""",
    re.IGNORECASE,
)

# vite preload helper: __vitePreload(() => import(...), ...)
_VITE_PRELOAD_RE = re.compile(
    r"""(?:_?_vitePreload|__vite__mapDeps)\s*\(\s*(?:\(\s*\)\s*=>\s*)?import\s*\(\s*['"`]([^'"`]+)['"`]""",
)

# webpack entry points from __webpack_require__.e([chunkId, ...])
_WEBPACK_ENTRY_RE = re.compile(
    r"""__webpack_require__\s*\.\s*(?:e|u)\s*\(\s*(['"`]?[\w-]+['"`]?)\s*\)""",
)


def _extract_webpack(content: str, source_url: str) -> list[AssetGraphNode]:
    """Extract one root node (the file itself) plus named chunk nodes.

    The root node carries static_imports and dynamic_imports so callers can
    check has_dynamic_imports by inspecting the root node's field directly.
    Named chunk nodes are added for every dynamic import() that has a
    webpackChunkName comment — these let the graph identify chunk names.
    """
    static_imports = list(dict.fromkeys(m.group(1) for m in _STATIC_IMPORT_RE.finditer(content)))

    dynamic_imports: list[str] = []
    chunk_names: dict[str, str] = {}  # url -> name
    seen_dyn: set[str] = set()

    for m in _DYNAMIC_IMPORT_RE.finditer(content):
        chunk_url = m.group(1)
        if chunk_url in seen_dyn:
            continue
        seen_dyn.add(chunk_url)
        dynamic_imports.append(chunk_url)
        # Chunk name may appear INSIDE the match (between `import(` and the url)
        # or in the 80 chars before the match.
        search_region = content[max(0, m.start() - 80): m.end()]
        name_m = _WEBPACK_CHUNK_NAME_RE.search(search_region)
        if name_m:
            chunk_names[chunk_url] = name_m.group(1)

    # require.ensure chunks
    for m in _WEBPACK_ENSURE_RE.finditer(content):
        for url_m in re.finditer(r"""['"`]([^'"`]+)['"`]""", m.group(1)):
            u = url_m.group(1)
            if u not in seen_dyn:
                seen_dyn.add(u)
                dynamic_imports.append(u)

    nodes: list[AssetGraphNode] = []

    # Root node: represents this file, with all its imports listed
    if static_imports or dynamic_imports:
        nodes.append(
            AssetGraphNode(
                chunk_name=None,
                chunk_url=source_url,
                bundler="webpack",
                static_imports=static_imports,
                dynamic_imports=dynamic_imports,
                source_url=source_url,
            )
        )

    # Named chunk nodes (one per named dynamic import)
    for url, name in chunk_names.items():
        nodes.append(
            AssetGraphNode(
                chunk_name=name,
                chunk_url=url,
                bundler="webpack",
                source_url=source_url,
            )
        )

    return nodes


def _extract_vite(content: str, source_url: str) -> list[AssetGraphNode]:
    seen: set[str] = set()
    nodes: list[AssetGraphNode] = []
    static_imports = [m.group(1) for m in _STATIC_IMPORT_RE.finditer(content)]

    for m in _VITE_PRELOAD_RE.finditer(content):
        u = m.group(1)
        if u in seen:
            continue
        seen.add(u)
        nodes.append(
            AssetGraphNode(chunk_name=None, chunk_url=u, bundler="vite", source_url=source_url)
        )

    # Also capture plain dynamic imports in vite bundles
    for m in _DYNAMIC_IMPORT_RE.finditer(content):
        u = m.group(1)
        if u in seen:
            continue
        seen.add(u)
        nodes.append(
            AssetGraphNode(chunk_name=None, chunk_url=u, bundler="vite", source_url=source_url)
        )

    if static_imports and nodes:
        nodes[0] = nodes[0].model_copy(update={"static_imports": list(dict.fromkeys(static_imports))})
    return nodes


def _extract_next(content: str, source_url: str) -> list[AssetGraphNode]:
    seen: set[str] = set()
    nodes: list[AssetGraphNode] = []

    for m in _NEXT_CHUNK_URL_RE.finditer(content):
        u = "/_next/static/chunks/" + m.group(1)
        if u in seen:
            continue
        seen.add(u)
        # Chunk name = filename without hash
        base = m.group(1).rsplit(".", 2)[0]  # strip .hash.js or .js
        nodes.append(
            AssetGraphNode(chunk_name=base, chunk_url=u, bundler="next", source_url=source_url)
        )

    for m in _DYNAMIC_IMPORT_RE.finditer(content):
        u = m.group(1)
        if u in seen:
            continue
        seen.add(u)
        nodes.append(
            AssetGraphNode(chunk_name=None, chunk_url=u, bundler="next", source_url=source_url)
        )

    return nodes


def _extract_vite_manifest(manifest: dict, source_url: str) -> list[AssetGraphNode]:
    """Parse a Vite manifest.json into AssetGraphNodes."""
    nodes: list[AssetGraphNode] = []
    for entry_key, info in manifest.items():
        if not isinstance(info, dict):
            continue
        chunk_url = info.get("file", "")
        if not chunk_url:
            continue
        nodes.append(
            AssetGraphNode(
                chunk_name=entry_key,
                chunk_url=chunk_url,
                bundler="vite",
                static_imports=info.get("imports", []),
                dynamic_imports=info.get("dynamicImports", []),
                source_url=source_url,
            )
        )
    return nodes


def build_asset_graph(
    file_contents: dict[str, str],
    manifest_contents: dict[str, dict] | None = None,
) -> AssetGraph:
    """Build an asset dependency graph from JS file contents and optional manifests.

    `file_contents` maps source URL → JS text.
    `manifest_contents` maps source URL → parsed JSON (Vite manifest.json).

    The returned AssetGraph aggregates nodes from all files.
    """
    all_nodes: list[AssetGraphNode] = []
    entry_points: list[str] = []
    # Track detected bundlers even for files that yield no extractable nodes
    detected_bundler_scores: dict[str, int] = {}

    # Vite manifest (highest fidelity)
    if manifest_contents:
        for url, manifest in manifest_contents.items():
            nodes = _extract_vite_manifest(manifest, url)
            all_nodes.extend(nodes)
            entry_points.extend(
                n.chunk_url for n in nodes if n.chunk_name and not n.chunk_name.startswith("_")
            )
            detected_bundler_scores["vite"] = detected_bundler_scores.get("vite", 0) + 1

    for url, content in file_contents.items():
        bundler = _detect_bundler(content)
        if bundler != "unknown":
            detected_bundler_scores[bundler] = detected_bundler_scores.get(bundler, 0) + 1

        if bundler == "webpack":
            nodes = _extract_webpack(content, url)
        elif bundler == "vite":
            nodes = _extract_vite(content, url)
        elif bundler == "next":
            nodes = _extract_next(content, url)
        else:
            # Generic: collect dynamic imports
            dyn = list(dict.fromkeys(m.group(1) for m in _DYNAMIC_IMPORT_RE.finditer(content)))
            sta = list(dict.fromkeys(m.group(1) for m in _STATIC_IMPORT_RE.finditer(content)))
            if dyn or sta:
                nodes = [
                    AssetGraphNode(
                        chunk_name=None,
                        chunk_url=url,
                        bundler="unknown",
                        static_imports=sta,
                        dynamic_imports=dyn,
                        source_url=url,
                    )
                ]
            else:
                nodes = []

        all_nodes.extend(nodes)

    # Dedup by chunk_url
    unique: dict[str, AssetGraphNode] = {}
    for node in all_nodes:
        if node.chunk_url not in unique:
            unique[node.chunk_url] = node

    nodes_list = sorted(unique.values(), key=lambda n: n.chunk_url)
    # Node-level bundler counts
    node_bundler_counts: dict[str, int] = {}
    for n in nodes_list:
        node_bundler_counts[n.bundler] = node_bundler_counts.get(n.bundler, 0) + 1

    # Dominant bundler: prefer node evidence, fall back to file-level detection
    combined = {**detected_bundler_scores}
    for b, cnt in node_bundler_counts.items():
        if b != "unknown":
            combined[b] = combined.get(b, 0) + cnt
    dominant_bundler = max(combined, key=combined.__getitem__) if combined else "unknown"

    has_dynamic = any(n.dynamic_imports for n in nodes_list)

    return AssetGraph(
        nodes=nodes_list,
        bundler=dominant_bundler,
        total_chunks=len(nodes_list),
        has_dynamic_imports=has_dynamic,
        entry_points=sorted(set(entry_points)),
    )
