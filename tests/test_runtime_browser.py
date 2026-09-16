from __future__ import annotations

import asyncio
from typing import Any

import pytest

from bundlebleed.runtime.browser import capture_page
from bundlebleed.scope.models import MatchType, ScopeConfig, ScopeEntry

pytest.importorskip("playwright", reason="playwright is an optional dependency")

from bundlebleed.scope.guard import ScopeGuard  # noqa: E402


def _scope() -> ScopeConfig:
    return ScopeConfig(in_scope=[ScopeEntry(domain="example.com", match_type=MatchType.WILDCARD)])


def _data_url(html: str) -> str:
    return f"data:text/html,{html}"


async def _fulfill_locally(route: Any) -> None:
    """Used as `on_allowed` in every test here: answers an "allowed"
    request from Playwright itself, so it NEVER actually reaches the real
    network, no matter what host it names."""
    await route.fulfill(status=200, content_type="application/javascript", body="// ok")


def test_out_of_scope_fetch_is_aborted() -> None:
    guard = ScopeGuard(_scope())
    html = (
        "<html><body><script>"
        "fetch('https://not-in-scope.invalid/x').catch(()=>{});"
        "</script></body></html>"
    )

    capture = asyncio.run(
        capture_page(_data_url(html), guard, timeout_seconds=5.0, on_allowed=_fulfill_locally)
    )

    denied = [e for e in capture.events if e.url == "https://not-in-scope.invalid/x"]
    assert len(denied) == 1
    assert denied[0].allowed is False


def test_out_of_scope_top_level_redirect_is_aborted() -> None:
    """A page that tries to navigate itself (window.location) to an
    out-of-scope host must be blocked the same as any subresource fetch —
    proving Invariant 2 holds even for navigations the page triggers."""
    guard = ScopeGuard(_scope())
    html = (
        "<html><body><script>"
        "window.location = 'https://not-in-scope.invalid/phish';"
        "</script></body></html>"
    )

    capture = asyncio.run(
        capture_page(_data_url(html), guard, timeout_seconds=5.0, on_allowed=_fulfill_locally)
    )

    redirect_events = [e for e in capture.events if "not-in-scope.invalid" in e.url]
    assert len(redirect_events) == 1
    assert redirect_events[0].allowed is False


def test_in_scope_requests_are_recorded_as_allowed_and_fulfilled_locally() -> None:
    guard = ScopeGuard(_scope())
    html = (
        "<html><body><script>"
        "fetch('https://example.com/api/v1/ping').catch(()=>{});"
        "</script></body></html>"
    )

    capture = asyncio.run(
        capture_page(_data_url(html), guard, timeout_seconds=5.0, on_allowed=_fulfill_locally)
    )

    allowed = [e for e in capture.events if e.url == "https://example.com/api/v1/ping"]
    assert len(allowed) == 1
    assert allowed[0].allowed is True


def test_capture_page_never_raises_on_a_navigation_failure() -> None:
    """A malformed page URL fails Playwright's own client-side validation
    before any DNS lookup or connection is attempted — no network activity
    at all — and capture_page must still return normally, not raise."""
    guard = ScopeGuard(_scope())
    capture = asyncio.run(capture_page("http://", guard, timeout_seconds=3.0))
    assert capture.page_url == "http://"
    assert capture.events == []


def test_discovered_js_urls_only_includes_allowed_script_requests() -> None:
    guard = ScopeGuard(_scope())
    html = (
        "<html><body>"
        "<script src='https://example.com/app.js'></script>"
        "<script>fetch('https://not-in-scope.invalid/evil.js').catch(()=>{});</script>"
        "</body></html>"
    )

    capture = asyncio.run(
        capture_page(_data_url(html), guard, timeout_seconds=5.0, on_allowed=_fulfill_locally)
    )

    assert "https://example.com/app.js" in capture.discovered_js_urls
    assert "https://not-in-scope.invalid/evil.js" not in capture.discovered_js_urls


def test_session_name_is_carried_onto_the_capture_result() -> None:
    guard = ScopeGuard(_scope())

    capture = asyncio.run(
        capture_page(
            _data_url("<html></html>"),
            guard,
            timeout_seconds=5.0,
            on_allowed=_fulfill_locally,
            cookie_header="session=abc123",
            session_name="admin",
        )
    )

    assert capture.session_name == "admin"


def test_unauthenticated_capture_has_no_session_name() -> None:
    guard = ScopeGuard(_scope())

    capture = asyncio.run(
        capture_page(
            _data_url("<html></html>"), guard, timeout_seconds=5.0, on_allowed=_fulfill_locally
        )
    )

    assert capture.session_name is None


def test_cookie_header_is_attached_to_every_request_the_context_makes() -> None:
    """A page that's gated on auth state only lazy-loads its authenticated
    chunk if the request actually carries the session cookie — this proves
    the cookie reaches the request, not just that it was accepted as an
    argument."""
    guard = ScopeGuard(_scope())
    html = (
        "<html><body><script>"
        "fetch('https://example.com/admin-chunk.js').catch(()=>{});"
        "</script></body></html>"
    )
    seen_cookie_headers: list[str | None] = []

    async def _record_cookie_and_fulfill(route: Any) -> None:
        headers = route.request.headers
        seen_cookie_headers.append(headers.get("cookie"))
        await route.fulfill(status=200, content_type="application/javascript", body="// ok")

    asyncio.run(
        capture_page(
            _data_url(html),
            guard,
            timeout_seconds=5.0,
            on_allowed=_record_cookie_and_fulfill,
            cookie_header="session=abc123",
        )
    )

    assert "session=abc123" in seen_cookie_headers
