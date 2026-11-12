from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from bundlebleed.auth.html_scripts import extract_script_urls
from bundlebleed.models import Endpoint, ThirdPartyScript

_LINK_HREF_RE = re.compile(r"""<a[^>]+href=["']([^"'#][^"']*)["']""", re.IGNORECASE)
_FORM_TAG_RE = re.compile(r"<form\b[^>]*>", re.IGNORECASE)
_ACTION_ATTR_RE = re.compile(r"""\baction=["']([^"']*)["']""", re.IGNORECASE)
_METHOD_ATTR_RE = re.compile(r"""\bmethod=["']([^"']*)["']""", re.IGNORECASE)
_SKIPPED_SCHEMES = ("javascript:", "mailto:", "tel:")


def _same_origin(url: str, page_url: str) -> bool:
    a, b = urlparse(url), urlparse(page_url)
    return (a.scheme, a.netloc) == (b.scheme, b.netloc)


def _path_and_query(url: str) -> str:
    parsed = urlparse(url)
    return parsed.path + (f"?{parsed.query}" if parsed.query else "")


def extract_html_endpoints(html: str, page_url: str) -> list[Endpoint]:
    """Pull plain server-rendered page routes out of HTML — `<a href>` links
    and `<form action>` targets — that the JS-focused endpoint patterns in
    `endpoints.py` never see (they only recognize `/api/...`, `fetch()`/
    `axios()`, GraphQL, WebSocket, and similar JS-embedded API call shapes).
    A classic page route like `/product?productId=1` or a form posting to
    `/my-account/change-email` is just as real an attack surface. Same-origin
    only; relative URLs are resolved against `page_url`."""
    findings: dict[tuple[str, str], Endpoint] = {}

    for match in _LINK_HREF_RE.finditer(html):
        href = match.group(1).strip()
        if href.startswith(_SKIPPED_SCHEMES):
            continue
        resolved = urljoin(page_url, href)
        if not _same_origin(resolved, page_url):
            continue
        path = _path_and_query(resolved)
        key = ("html_link", path)
        findings.setdefault(
            key, Endpoint(value=path, pattern_name="html_link", source_url=page_url)
        )

    for tag_match in _FORM_TAG_RE.finditer(html):
        tag = tag_match.group(0)
        action_match = _ACTION_ATTR_RE.search(tag)
        action = action_match.group(1).strip() if action_match else ""
        if action.startswith(_SKIPPED_SCHEMES):
            continue
        resolved = urljoin(page_url, action) if action else page_url
        if not _same_origin(resolved, page_url):
            continue
        method_match = _METHOD_ATTR_RE.search(tag)
        method = method_match.group(1).lower() if method_match else "get"
        pattern_name = "html_form_post" if method == "post" else "html_form_get"
        path = _path_and_query(resolved)
        key = (pattern_name, path)
        findings.setdefault(
            key, Endpoint(value=path, pattern_name=pattern_name, source_url=page_url)
        )

    return list(findings.values())


def extract_third_party_scripts(html: str, page_url: str) -> list[ThirdPartyScript]:
    """Client-side supply-chain surface: every `<script src>` served from a
    domain other than the page's own. Pure discovery — never a claim that
    the third-party host is compromised or vulnerable, just that it's part
    of the attack surface (a takeover or compromise of it puts
    attacker-controlled JS directly on this page)."""
    findings: dict[tuple[str, str], ThirdPartyScript] = {}
    for script_url in extract_script_urls(html, page_url):
        if _same_origin(script_url, page_url):
            continue
        hostname = urlparse(script_url).hostname or script_url
        key = (hostname, script_url)
        findings.setdefault(
            key, ThirdPartyScript(hostname=hostname, script_url=script_url, page_url=page_url)
        )
    return list(findings.values())
