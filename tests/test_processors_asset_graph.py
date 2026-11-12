from __future__ import annotations

from bundlebleed.processors.asset_graph import AssetGraph, build_asset_graph


def test_webpack_dynamic_import_detected() -> None:
    js = """
    __webpack_require__(42);
    import(/* webpackChunkName: "dashboard" */ './dashboard');
    """
    graph = build_asset_graph({"https://example.com/main.js": js})
    assert any("dashboard" in n.chunk_url for n in graph.nodes)


def test_webpack_chunk_name_extracted() -> None:
    js = """
    __webpack_require__(1);
    import(/* webpackChunkName: "admin-panel" */ './admin');
    """
    graph = build_asset_graph({"https://example.com/main.js": js})
    named = [n for n in graph.nodes if n.chunk_name == "admin-panel"]
    assert len(named) >= 1


def test_webpack_bundler_detected() -> None:
    js = "__webpack_require__(0); webpackChunkApp = [];"
    graph = build_asset_graph({"https://example.com/app.js": js})
    assert graph.bundler == "webpack"


def test_vite_preload_detected() -> None:
    js = """
    __vitePreload(() => import('./components/Modal.vue'), []);
    """
    graph = build_asset_graph({"https://example.com/main.js": js})
    assert any("Modal" in n.chunk_url for n in graph.nodes)
    assert graph.bundler == "vite"


def test_next_chunk_url_detected() -> None:
    js = """
    __NEXT_DATA__ = {};
    loadChunk('/_next/static/chunks/pages/index.abc123.js');
    """
    graph = build_asset_graph({"https://example.com/_next/main.js": js})
    assert any("/_next/static/chunks" in n.chunk_url for n in graph.nodes)


def test_vite_manifest_parsed() -> None:
    manifest = {
        "src/main.ts": {
            "file": "assets/main.abc123.js",
            "imports": ["assets/vendor.xyz.js"],
            "dynamicImports": ["assets/dashboard.def.js"],
        }
    }
    graph = build_asset_graph({}, manifest_contents={"https://example.com/manifest.json": manifest})
    main = [n for n in graph.nodes if n.chunk_name == "src/main.ts"]
    assert len(main) >= 1
    assert "assets/vendor.xyz.js" in main[0].static_imports
    assert "assets/dashboard.def.js" in main[0].dynamic_imports


def test_has_dynamic_imports_flag() -> None:
    js = "__webpack_require__(1); import('./lazy-route');"
    graph = build_asset_graph({"https://example.com/app.js": js})
    assert graph.has_dynamic_imports is True


def test_no_dynamic_imports() -> None:
    js = "const x = 1; console.log(x);"
    graph = build_asset_graph({"https://example.com/app.js": js})
    assert graph.has_dynamic_imports is False


def test_total_chunks_count() -> None:
    # Root node has dynamic_imports listing ./a, ./b, ./c
    js = """
    __webpack_require__(1);
    import('./a');
    import('./b');
    import('./c');
    """
    graph = build_asset_graph({"https://example.com/main.js": js})
    root = [n for n in graph.nodes if n.chunk_url == "https://example.com/main.js"]
    assert len(root) >= 1
    assert len(root[0].dynamic_imports) >= 3
    assert graph.has_dynamic_imports is True


def test_deduplication() -> None:
    # Duplicate import('./shared') should appear only once in dynamic_imports
    js = """
    __webpack_require__(1);
    import('./shared');
    import('./shared');
    """
    graph = build_asset_graph({"https://example.com/main.js": js})
    root = [n for n in graph.nodes if n.chunk_url == "https://example.com/main.js"]
    assert len(root) == 1
    shared_refs = [u for u in root[0].dynamic_imports if "./shared" in u]
    assert len(shared_refs) == 1


def test_empty_input() -> None:
    graph = build_asset_graph({})
    assert isinstance(graph, AssetGraph)
    assert graph.total_chunks == 0
