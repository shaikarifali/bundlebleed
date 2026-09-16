from __future__ import annotations

from typing import Any

from bundlebleed.runtime.interceptor import RouteHandler, make_route_handler
from bundlebleed.runtime.models import RuntimeCapture, RuntimeEvent
from bundlebleed.scope.guard import ScopeGuard


class PlaywrightNotInstalledError(RuntimeError):
    pass


def _import_async_playwright() -> Any:
    try:
        from playwright.async_api import async_playwright
    except ImportError as exc:
        raise PlaywrightNotInstalledError(
            "playwright is not installed. Run: uv pip install 'bundlebleed[runtime]' "
            "&& playwright install chromium"
        ) from exc
    return async_playwright


async def capture_page(
    page_url: str,
    guard: ScopeGuard,
    timeout_seconds: float = 15.0,
    on_allowed: RouteHandler | None = None,
    cookie_header: str | None = None,
    session_name: str | None = None,
) -> RuntimeCapture:
    """Load `page_url` in headless Chromium and record every request the
    page makes. Every request — including a same-page redirect to a
    different host — is checked against ScopeGuard before being allowed
    through; a denied one is aborted, never sent.

    Purely observational: no clicks, no form submission, no keystrokes.
    Dialogs (alert/confirm/prompt) are auto-dismissed; downloads are
    disabled. A hard per-page timeout bounds a slow or malicious page —
    a page that fails to load within it is not treated as a scan failure.

    `cookie_header`, if given, is attached as a raw `Cookie` header on
    every request the browser context makes (same mechanism as the
    unauthenticated-vs-authenticated static crawl: a header injection, not
    a real cookie jar). This is what lets an SPA's client-side routing
    render an authenticated-only view — and lazy-load the JS chunk behind
    it — the same way it would for a logged-in user in a real browser.
    Still no login is performed: the cookie must already be provided.
    `session_name` is carried through onto the result purely for
    provenance (which session, if any, produced this capture) — the
    cookie value itself is never stored on the result.

    `on_allowed` defaults to the real `route.continue_()`. Tests pass a
    local `route.fulfill(...)` here so an "allowed" decision never actually
    reaches the real network.
    """
    async_playwright = _import_async_playwright()

    events: list[RuntimeEvent] = []
    handler = make_route_handler(guard, events, on_allowed=on_allowed)

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        try:
            context = await browser.new_context(accept_downloads=False)
            if cookie_header:
                await context.set_extra_http_headers({"Cookie": cookie_header})
            page = await context.new_page()
            page.on("dialog", lambda dialog: dialog.dismiss())
            await page.route("**/*", handler)

            try:
                await page.goto(page_url, timeout=timeout_seconds * 1000)
                await page.wait_for_timeout(min(timeout_seconds * 1000, 3000))
            except Exception:
                # The target page is untrusted content; a load failure,
                # timeout, or crash there must never abort the whole scan.
                pass
        finally:
            await browser.close()

    discovered_js = sorted({e.url for e in events if e.allowed and e.resource_type == "script"})
    return RuntimeCapture(
        page_url=page_url,
        events=events,
        discovered_js_urls=discovered_js,
        session_name=session_name,
    )


async def capture_runtime(
    page_urls: list[str],
    guard: ScopeGuard,
    max_pages: int = 10,
    timeout_seconds: float = 15.0,
    on_allowed: RouteHandler | None = None,
    cookie_header: str | None = None,
    session_name: str | None = None,
) -> list[RuntimeCapture]:
    """Capture at most `max_pages` pages, one at a time (sequential, not
    parallel, to keep browser resource usage bounded and predictable)."""
    captures = []
    for url in page_urls[:max_pages]:
        captures.append(
            await capture_page(
                url,
                guard,
                timeout_seconds=timeout_seconds,
                on_allowed=on_allowed,
                cookie_header=cookie_header,
                session_name=session_name,
            )
        )
    return captures
