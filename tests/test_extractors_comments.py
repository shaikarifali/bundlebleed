from __future__ import annotations

from bundlebleed.extractors.comments import extract_comments


def test_single_line_comment_flagged() -> None:
    js = "// TODO: remove this admin bypass before prod\nconst x = 1;"
    comments, flags = extract_comments(js, "https://example.com/app.js")
    assert any("todo" in c.keyword_matched for c in comments)
    assert any("bypass" in c.keyword_matched or "admin" in c.keyword_matched for c in comments)


def test_block_comment_flagged() -> None:
    js = "/* hardcoded password = secret123 */\nfunction foo() {}"
    comments, _ = extract_comments(js, "https://example.com/app.js")
    assert len(comments) >= 1
    assert any("password" in c.keyword_matched or "hardcoded" in c.keyword_matched for c in comments)


def test_benign_comment_not_flagged() -> None:
    js = "// This function calculates the sum of two numbers\nfunction add(a, b) { return a + b; }"
    comments, _ = extract_comments(js, "https://example.com/app.js")
    assert comments == []


def test_feature_flag_launchdarkly() -> None:
    js = "if (LaunchDarkly.variation('new-admin-panel', false)) { showPanel(); }"
    _, flags = extract_comments(js, "https://example.com/app.js")
    assert len(flags) >= 1


def test_feature_flag_is_enabled() -> None:
    js = "if (features.isEnabled('internal_debug_mode')) { enableDebug(); }"
    _, flags = extract_comments(js, "https://example.com/app.js")
    assert len(flags) >= 1
    assert any("internal_debug_mode" in f.key for f in flags)


def test_feature_flag_const() -> None:
    js = "const FEATURE_ADMIN_DASHBOARD = true;"
    _, flags = extract_comments(js, "https://example.com/app.js")
    assert len(flags) >= 1


def test_no_flags_in_plain_code() -> None:
    js = "const x = getUserProfile(); return x.name;"
    _, flags = extract_comments(js, "https://example.com/app.js")
    assert flags == []


def test_provenance_fields() -> None:
    js = "// FIXME: auth disabled for testing"
    comments, _ = extract_comments(js, "https://example.com/app.js", file="/tmp/app.js")
    assert comments[0].source_url == "https://example.com/app.js"
    assert comments[0].file == "/tmp/app.js"
    assert comments[0].line == 1


def test_deduplication() -> None:
    js = "// TODO: fix this\n// TODO: fix this\n"
    comments, _ = extract_comments(js, "https://example.com/a.js")
    todo_comments = [c for c in comments if "todo" in c.keyword_matched]
    assert len(todo_comments) == 1
