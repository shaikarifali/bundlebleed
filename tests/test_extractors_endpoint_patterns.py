from __future__ import annotations

from bundlebleed.extractors.endpoints import extract_endpoints


def _values(content: str) -> set[str]:
    return {e.value for e in extract_endpoints(content, source_url="x")}


def _method_for(content: str, value: str, pattern_name: str) -> str | None:
    matches = [
        e
        for e in extract_endpoints(content, source_url="x")
        if e.value == value and e.pattern_name == pattern_name
    ]
    assert len(matches) == 1, f"expected exactly one {pattern_name!r} endpoint {value!r}"
    return matches[0].method


def test_jquery_get_post_call() -> None:
    assert "/api/v1/search" in _values('$.get("/api/v1/search", function(data) {});')
    assert "/api/v1/comments" in _values('$.post("/api/v1/comments", payload);')


def test_axios_shorthand_call() -> None:
    assert "/api/v1/users/123" in _values('axios("/api/v1/users/123").then(r => r.data);')


def test_axios_shorthand_does_not_fire_on_axios_dot_method_calls() -> None:
    # axios.get(...) is already covered by the existing axios_call pattern —
    # the new shorthand pattern (bare "axios(") must not also fire on it.
    endpoints = extract_endpoints('axios.get("/api/v2/orders/{id}");', source_url="x")
    pattern_names = {e.pattern_name for e in endpoints}
    assert "axios_shorthand" not in pattern_names


def test_axios_config_object_call() -> None:
    content = "axios({ method: 'post', url: '/api/v1/upload', data: form });"
    assert "/api/v1/upload" in _values(content)


def test_xhr_open_call() -> None:
    assert "/api/v1/status" in _values('xhr.open("GET", "/api/v1/status");')
    assert "/api/v1/submit" in _values("xhr.open('POST', '/api/v1/submit');")


def test_xhr_open_requires_a_real_http_method() -> None:
    # Not every ".open(" call is an XHR request (e.g. a modal/dialog widget).
    assert extract_endpoints('modal.open("dialog-content");', source_url="x") == []


def test_send_beacon_call() -> None:
    assert "/api/v1/analytics" in _values('navigator.sendBeacon("/api/v1/analytics", data);')


def test_clean_bundle_still_finds_nothing_with_new_patterns() -> None:
    content = 'function add(a, b) { return a + b; } console.log("hello");'
    assert extract_endpoints(content, source_url="x") == []


def test_rest_api_path_matches_internal_gateway_prefix() -> None:
    # A very common real-world convention for the endpoints nobody links from
    # the UI: '/api-internal/...', '/api-int/...', etc. -- not just '/api/'.
    assert "/api-internal/v2/invoice-ar/proxy" in _values(
        'const url = "/api-internal/v2/invoice-ar/proxy?organizationId=" + orgId;'
    )
    assert "/api-int/v1/export" in _values('customerProxy: "/api-int/v1/export",')


def test_rest_api_path_still_matches_plain_api_prefix() -> None:
    assert "/api/v1/legacy/billing/run-settlement" in _values(
        'legacyBilling: "/api/v1/legacy/billing/run-settlement",'
    )


def test_axios_call_captures_the_verb_as_method() -> None:
    assert _method_for('axios.get("/api/v1/orders");', "/api/v1/orders", "axios_call") == "GET"
    assert (
        _method_for('axios.delete("/api/v1/orders/9");', "/api/v1/orders/9", "axios_call")
        == "DELETE"
    )


def test_jquery_get_post_captures_the_verb_as_method() -> None:
    assert _method_for('$.get("/api/v1/search");', "/api/v1/search", "jquery_get_post") == "GET"
    assert (
        _method_for('$.post("/api/v1/comments");', "/api/v1/comments", "jquery_get_post") == "POST"
    )


def test_xhr_open_captures_the_verb_as_method() -> None:
    assert _method_for('xhr.open("GET", "/api/v1/status");', "/api/v1/status", "xhr_open") == "GET"
    assert (
        _method_for("xhr.open('DELETE', '/api/v1/item/1');", "/api/v1/item/1", "xhr_open")
        == "DELETE"
    )


def test_send_beacon_is_always_reported_as_post() -> None:
    assert (
        _method_for(
            'navigator.sendBeacon("/api/v1/analytics", data);',
            "/api/v1/analytics",
            "send_beacon",
        )
        == "POST"
    )


def test_ambiguous_call_shapes_do_not_assert_a_method() -> None:
    # fetch(), bare axios(), and $.ajax() default to GET only when no
    # options object overrides it -- never guessed, since the source text
    # alone doesn't say either way.
    assert _method_for('fetch("/api/v1/profile");', "/api/v1/profile", "fetch_call") is None
    assert (
        _method_for('axios("/api/v1/users/123");', "/api/v1/users/123", "axios_shorthand") is None
    )
