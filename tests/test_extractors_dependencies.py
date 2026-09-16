from __future__ import annotations

from bundlebleed.extractors.dependencies import extract_vulnerable_libraries


def test_old_jquery_banner_is_flagged() -> None:
    content = "/*! jQuery v3.4.1 | (c) JS Foundation and other contributors */"
    findings = extract_vulnerable_libraries(content, source_url="https://e.com/vendor.js")
    names = {f.library_name for f in findings}
    assert "jquery" in names
    finding = next(f for f in findings if f.library_name == "jquery")
    assert finding.detected_version == "3.4.1"
    assert finding.severity == "high"
    assert "CVE-2020-11022" in finding.cve


def test_patched_jquery_banner_is_not_flagged() -> None:
    content = "/*! jQuery v3.6.0 | (c) JS Foundation and other contributors */"
    findings = extract_vulnerable_libraries(content, source_url="https://e.com/vendor.js")
    assert findings == []


def test_old_lodash_banner_is_flagged() -> None:
    content = "/**\n * @license\n * Lodash <https://lodash.com/>\n * Version 4.17.15\n */"
    findings = extract_vulnerable_libraries(content, source_url="https://e.com/vendor.js")
    names = {f.library_name for f in findings}
    assert "lodash" in names


def test_patched_lodash_banner_is_not_flagged() -> None:
    content = "/**\n * Lodash\n * Version 4.17.21\n */"
    findings = extract_vulnerable_libraries(content, source_url="https://e.com/vendor.js")
    assert findings == []


def test_old_angularjs_banner_is_flagged() -> None:
    content = "/**\n * @license AngularJS v1.7.8\n * (c) 2010-2018 Google\n */"
    findings = extract_vulnerable_libraries(content, source_url="https://e.com/vendor.js")
    names = {f.library_name for f in findings}
    assert "angularjs" in names


def test_no_banner_present_produces_no_finding() -> None:
    findings = extract_vulnerable_libraries("const x = 1;", source_url="https://e.com/app.js")
    assert findings == []


def test_multiple_libraries_in_one_file_are_all_reported() -> None:
    content = (
        "/*! jQuery v3.4.1 */\n"
        "/**\n * Lodash\n * Version 4.17.15\n */\n"
        "/**\n * @license AngularJS v1.7.8\n */"
    )
    findings = extract_vulnerable_libraries(content, source_url="https://e.com/vendor.js")
    names = {f.library_name for f in findings}
    assert names == {"jquery", "lodash", "angularjs"}
