from __future__ import annotations

from bundlebleed.extractors.proto_pollution import (
    extract_proto_pollution,
    proto_pollution_risk_flags,
)


def test_level1_direct_proto_dot_write() -> None:
    js = "obj.__proto__.isAdmin = true;"
    findings = extract_proto_pollution(js, "https://example.com/app.js")
    l1 = [f for f in findings if f.level == 1]
    assert len(l1) >= 1


def test_level1_proto_object_assign() -> None:
    js = "target.__proto__ = { admin: true };"
    findings = extract_proto_pollution(js, "https://example.com/app.js")
    assert any(f.level == 1 for f in findings)


def test_level2_constructor_prototype() -> None:
    js = "obj.constructor.prototype.isAdmin = true;"
    findings = extract_proto_pollution(js, "https://example.com/app.js")
    l2 = [f for f in findings if f.level == 2]
    assert len(l2) >= 1


def test_level3_lodash_merge() -> None:
    js = "_.merge(target, userInput);"
    findings = extract_proto_pollution(js, "https://example.com/app.js")
    l3 = [f for f in findings if f.level == 3]
    assert len(l3) >= 1
    assert any(f.pattern_name == "lodash_merge" for f in l3)


def test_level3_jquery_extend_deep() -> None:
    js = "jQuery.extend(true, {}, userConfig);"
    findings = extract_proto_pollution(js, "https://example.com/app.js")
    assert any(f.level == 3 and "jquery" in f.pattern_name.lower() for f in findings)


def test_level5_object_prototype_write() -> None:
    js = "Object.prototype.toString = function() { return 'hacked'; };"
    findings = extract_proto_pollution(js, "https://example.com/app.js")
    l5 = [f for f in findings if f.level == 5]
    assert len(l5) >= 1


def test_sorted_by_level_desc() -> None:
    js = """
    Object.prototype.admin = true;
    _.merge(config, input);
    obj.__proto__.x = 1;
    """
    findings = extract_proto_pollution(js, "https://example.com/app.js")
    if len(findings) >= 2:
        assert findings[0].level >= findings[-1].level


def test_gadgets_detected() -> None:
    js = """
    _.merge(config, userInput);
    el.innerHTML = config.template;
    """
    findings = extract_proto_pollution(js, "https://example.com/app.js")
    assert any(len(f.gadgets) > 0 for f in findings)
    # innerHTML gadget should be detected
    all_gadgets = {g for f in findings for g in f.gadgets}
    assert "innerHTML_gadget" in all_gadgets


def test_benign_code_no_findings() -> None:
    js = "const x = { a: 1, b: 2 }; Object.assign(result, x);"
    findings = extract_proto_pollution(js, "https://example.com/app.js")
    assert findings == []


def test_risk_flags_l3() -> None:
    js = "_.merge(target, body);"
    findings = extract_proto_pollution(js, "https://example.com/app.js")
    flags = proto_pollution_risk_flags(findings)
    assert any("merge" in f.lower() or "pollut" in f.lower() for f in flags)


def test_provenance_fields() -> None:
    js = "obj.__proto__.x = 1;"
    findings = extract_proto_pollution(js, "https://example.com/app.js", file="/tmp/app.js")
    assert findings[0].file == "/tmp/app.js"
    assert findings[0].source_url == "https://example.com/app.js"
