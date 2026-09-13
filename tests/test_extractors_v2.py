from __future__ import annotations

from bundlebleed.extractors.dom_analysis import extract_dom_findings
from bundlebleed.extractors.parameters import extract_parameters
from bundlebleed.extractors.subdomains import extract_subdomains
from bundlebleed.scope.models import MatchType, ScopeConfig, ScopeEntry
from tests.conftest import FIXTURES_DIR

SUBDOMAINS_AND_PARAMS = (FIXTURES_DIR / "js" / "subdomains_and_params.js").read_text()
DOM_XSS_CANDIDATE = (FIXTURES_DIR / "js" / "dom_xss_candidate.js").read_text()
DOM_SINK_ONLY = (FIXTURES_DIR / "js" / "dom_sink_only.js").read_text()
CLEAN_BUNDLE = (FIXTURES_DIR / "js" / "clean_bundle.js").read_text()


def test_extract_subdomains_wildcard_scope_marks_them_in_scope() -> None:
    scope_config = ScopeConfig(
        in_scope=[ScopeEntry(domain="example.com", match_type=MatchType.WILDCARD)]
    )
    findings = extract_subdomains(
        SUBDOMAINS_AND_PARAMS, source_url="https://example.com/app.js", scope_config=scope_config
    )
    domains = {f.domain: f.in_scope for f in findings}

    assert domains["internal-api.example.com"] is True
    assert domains["admin.example.com"] is True
    assert "cdn.unrelated-domain.com" not in domains


def test_extract_subdomains_exact_scope_flags_for_manual_review() -> None:
    scope_config = ScopeConfig(
        in_scope=[ScopeEntry(domain="example.com", match_type=MatchType.EXACT)]
    )
    findings = extract_subdomains(
        SUBDOMAINS_AND_PARAMS, source_url="https://example.com/app.js", scope_config=scope_config
    )
    domains = {f.domain: f for f in findings}

    assert domains["internal-api.example.com"].in_scope is False
    assert "manual review" in domains["internal-api.example.com"].note


def test_extract_subdomains_clean_bundle_finds_nothing() -> None:
    scope_config = ScopeConfig(
        in_scope=[ScopeEntry(domain="example.com", match_type=MatchType.WILDCARD)]
    )
    assert extract_subdomains(CLEAN_BUNDLE, "https://example.com/clean.js", scope_config) == []


def test_extract_parameters_finds_interesting_names() -> None:
    findings = extract_parameters(SUBDOMAINS_AND_PARAMS, source_url="https://example.com/app.js")
    names = {f.name for f in findings}
    assert names == {"userId", "redirectUrl", "authToken", "isAdmin"}


def test_extract_parameters_does_not_match_substring_false_positives() -> None:
    # "hidden" contains "id" as a raw substring but must NOT match the "id" keyword.
    findings = extract_parameters("const hidden = true;", source_url="x")
    assert findings == []


def test_extract_parameters_finds_interesting_query_string_keys() -> None:
    findings = extract_parameters(
        "/product?productId=1&color=blue", source_url="https://example.com/product"
    )
    names = {f.name for f in findings}
    assert names == {"productId"}


def test_extract_parameters_query_string_does_not_match_substring_false_positives() -> None:
    findings = extract_parameters("/page?hidden=true", source_url="x")
    assert findings == []


def test_extract_dom_findings_flags_sink_with_cooccurring_source() -> None:
    findings = extract_dom_findings(DOM_XSS_CANDIDATE, source_url="https://example.com/app.js")
    sinks = {f.sink_pattern for f in findings}
    assert "inner_html" in sinks
    inner_html_finding = next(f for f in findings if f.sink_pattern == "inner_html")
    assert "location_hash" in inner_html_finding.co_occurring_sources


def test_extract_dom_findings_sink_without_source_is_not_reported() -> None:
    assert extract_dom_findings(DOM_SINK_ONLY, source_url="https://example.com/app.js") == []


def test_extract_dom_findings_clean_bundle_finds_nothing() -> None:
    assert extract_dom_findings(CLEAN_BUNDLE, source_url="https://example.com/clean.js") == []
