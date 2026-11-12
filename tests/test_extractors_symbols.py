from __future__ import annotations

from bundlebleed.extractors.symbols import extract_symbols


def test_window_global_detected() -> None:
    js = "window.AppConfig = { env: 'prod' };"
    symbols = extract_symbols(js, "https://example.com/app.js")
    names = [s.name for s in symbols]
    assert "AppConfig" in names
    assert any(s.kind == "global" for s in symbols if s.name == "AppConfig")


def test_export_function_detected() -> None:
    js = "export function getUserProfile(userId) { return fetch('/api/user/' + userId); }"
    symbols = extract_symbols(js, "https://example.com/app.js")
    names = [s.name for s in symbols]
    assert "getUserProfile" in names


def test_named_export_brace_detected() -> None:
    js = "export { getUserProfile, updateAccount, deleteUser };"
    symbols = extract_symbols(js, "https://example.com/app.js")
    names = [s.name for s in symbols]
    assert "getUserProfile" in names
    assert "updateAccount" in names
    assert "deleteUser" in names


def test_const_top_level_detected() -> None:
    js = "const API_BASE = 'https://api.example.com';"
    symbols = extract_symbols(js, "https://example.com/app.js")
    assert any(s.name == "API_BASE" and s.kind == "const" for s in symbols)


def test_module_exports_detected() -> None:
    js = "module.exports = router;"
    symbols = extract_symbols(js, "https://example.com/app.js")
    assert any(s.name == "router" and s.kind == "module" for s in symbols)


def test_deduplication() -> None:
    js = "const x = 1;\nconst x = 2;"
    symbols = extract_symbols(js, "https://example.com/app.js")
    x_syms = [s for s in symbols if s.name == "x"]
    assert len(x_syms) == 1


def test_provenance_fields() -> None:
    js = "window.MyApp = {};"
    symbols = extract_symbols(js, "https://example.com/app.js", file="/tmp/app.js")
    assert symbols[0].file == "/tmp/app.js"
    assert symbols[0].line == 1
