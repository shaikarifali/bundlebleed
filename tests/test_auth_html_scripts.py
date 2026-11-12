from __future__ import annotations

from bundlebleed.auth.html_scripts import extract_script_urls

HTML = """
<html>
<head>
  <script src="/static/app.js"></script>
  <script src="https://cdn.example.com/lib.js"></script>
</head>
<body>
  <script src='/admin/panel.js'></script>
  <script>console.log("inline, no src")</script>
</body>
</html>
"""


def test_extract_script_urls_resolves_relative_against_page_url() -> None:
    urls = extract_script_urls(HTML, "https://example.com/dashboard")
    assert "https://example.com/static/app.js" in urls
    assert "https://example.com/admin/panel.js" in urls


def test_extract_script_urls_keeps_absolute_urls_untouched() -> None:
    urls = extract_script_urls(HTML, "https://example.com/dashboard")
    assert "https://cdn.example.com/lib.js" in urls


def test_extract_script_urls_ignores_inline_scripts() -> None:
    urls = extract_script_urls(HTML, "https://example.com/dashboard")
    assert len(urls) == 3


def test_extract_script_urls_dedupes() -> None:
    html = '<script src="/app.js"></script><script src="/app.js"></script>'
    urls = extract_script_urls(html, "https://example.com/")
    assert urls == ["https://example.com/app.js"]


def test_extract_script_urls_empty_html_returns_empty_list() -> None:
    assert extract_script_urls("<html></html>", "https://example.com/") == []
