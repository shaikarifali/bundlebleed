from __future__ import annotations

from bundlebleed.extractors.html_links import extract_html_endpoints, extract_third_party_scripts

PAGE_URL = "https://example.com/"

SHOP_PAGE = """
<html>
<body>
<a href="/my-account">My account</a>
<a href="/product?productId=1">Product 1</a>
<a href="/product?productId=2">Product 2</a>
<a href="#top">Back to top</a>
<a href="javascript:void(0)">Do nothing</a>
<a href="https://other-domain.com/x">External link</a>
<form action="/my-account/change-email" method="POST">
    <input name="email">
</form>
<form action="/search">
    <input name="q">
</form>
</body>
</html>
"""


def test_extracts_same_origin_links_with_query_strings() -> None:
    endpoints = extract_html_endpoints(SHOP_PAGE, PAGE_URL)
    links = {e.value for e in endpoints if e.pattern_name == "html_link"}
    assert links == {"/my-account", "/product?productId=1", "/product?productId=2"}


def test_ignores_fragment_and_javascript_and_cross_origin_links() -> None:
    endpoints = extract_html_endpoints(SHOP_PAGE, PAGE_URL)
    values = {e.value for e in endpoints}
    assert not any("other-domain.com" in v for v in values)
    assert "#top" not in values


def test_extracts_form_actions_tagged_by_method() -> None:
    endpoints = extract_html_endpoints(SHOP_PAGE, PAGE_URL)
    by_pattern = {e.pattern_name: e.value for e in endpoints if "form" in e.pattern_name}
    assert by_pattern["html_form_post"] == "/my-account/change-email"
    assert by_pattern["html_form_get"] == "/search"


def test_relative_links_resolved_against_page_url() -> None:
    endpoints = extract_html_endpoints(
        '<a href="settings">Settings</a>', "https://example.com/account/"
    )
    assert endpoints[0].value == "/account/settings"


def test_clean_page_with_no_links_or_forms_finds_nothing() -> None:
    assert extract_html_endpoints("<html><body>Hello</body></html>", PAGE_URL) == []


THIRD_PARTY_PAGE = """
<html><body>
<script src="/static/app.js"></script>
<script src="https://cdn.jsdelivr.net/npm/some-lib@1.0.0/dist/lib.min.js"></script>
<script src="https://analytics.vendor.com/tracker.js"></script>
</body></html>
"""


def test_extract_third_party_scripts_finds_external_hosts_only() -> None:
    scripts = extract_third_party_scripts(THIRD_PARTY_PAGE, PAGE_URL)
    hostnames = {s.hostname for s in scripts}
    assert hostnames == {"cdn.jsdelivr.net", "analytics.vendor.com"}


def test_extract_third_party_scripts_excludes_same_origin_script() -> None:
    scripts = extract_third_party_scripts(THIRD_PARTY_PAGE, PAGE_URL)
    assert not any(s.script_url.endswith("/static/app.js") for s in scripts)


def test_extract_third_party_scripts_records_page_url() -> None:
    scripts = extract_third_party_scripts(THIRD_PARTY_PAGE, PAGE_URL)
    assert all(s.page_url == PAGE_URL for s in scripts)


def test_page_with_only_same_origin_scripts_finds_nothing() -> None:
    html = '<script src="/static/app.js"></script>'
    assert extract_third_party_scripts(html, PAGE_URL) == []
