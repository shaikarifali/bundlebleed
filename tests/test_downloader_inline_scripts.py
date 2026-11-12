from __future__ import annotations

from bundlebleed.downloader.fetcher import extract_inline_scripts


def test_basic_inline_script_extracted() -> None:
    html = """<html><body>
    <script>
      const apiKey = 'hardcoded-key-123';
      fetch('/api/data');
    </script>
    </body></html>"""
    files = extract_inline_scripts("https://example.com/page", html)
    assert len(files) == 1
    assert "fetch" in files[0].content


def test_external_script_skipped() -> None:
    html = '<script src="/app.js"></script>'
    files = extract_inline_scripts("https://example.com/page", html)
    assert files == []


def test_non_js_type_skipped() -> None:
    html = '<script type="application/ld+json">{"@context": "https://schema.org"}</script>'
    files = extract_inline_scripts("https://example.com/page", html)
    assert files == []


def test_multiple_scripts_extracted() -> None:
    html = """
    <script>var a = 1; var b = 2; var c = 3; var d = 4; var e = 5;</script>
    <script>var x = window.location.search; document.write(x);</script>
    """
    files = extract_inline_scripts("https://example.com/page", html)
    assert len(files) == 2


def test_synthetic_url_format() -> None:
    html = "<script>const x = 1; const y = 2; const z = 3; const w = 4;</script>"
    files = extract_inline_scripts("https://example.com/page", html)
    assert len(files) == 1
    assert files[0].url.startswith("inline:https://example.com/page#script-")


def test_too_short_script_skipped() -> None:
    html = "<script>x=1</script>"
    files = extract_inline_scripts("https://example.com/page", html)
    assert files == []


def test_module_type_script_extracted() -> None:
    html = """<script type="module">
    import { something } from './module.js';
    something.doThing();
    </script>"""
    files = extract_inline_scripts("https://example.com/page", html)
    assert len(files) == 1


def test_empty_html_no_error() -> None:
    files = extract_inline_scripts("https://example.com/page", "")
    assert files == []
