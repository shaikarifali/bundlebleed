from __future__ import annotations

import asyncio

import httpx
import pytest

from bundlebleed.downloader.fetcher import (
    fetch_js_files,
    fetch_page_files,
    looks_like_js,
    looks_like_page,
)
from bundlebleed.downloader.http_client import GuardedHttpClient
from bundlebleed.ratelimit import RateLimiter
from bundlebleed.scope.guard import ScopeGuard
from bundlebleed.scope.models import MatchType, ScopeConfig, ScopeEntry

FIXTURE_RESPONSES = {
    "https://api.example.com/app.js": (
        200,
        'console.log("hi");\n//# sourceMappingURL=app.js.map\n',
    ),
    "https://api.example.com/app.js.map": (200, '{"version":3,"sources":["app.ts"]}'),
    "https://api.example.com/broken.js": (500, "server error"),
    "https://api.example.com/plain.json": (200, "{}"),
    "https://api.example.com/product": (200, "<html>product page</html>"),
    "https://api.example.com/style.css": (200, "body { color: red; }"),
    "https://api.example.com/rich.js": (
        200,
        'console.log("hi");\n//# sourceMappingURL=rich.js.map\n',
    ),
    "https://api.example.com/rich.js.map": (
        200,
        '{"version":3,"sources":["src/secrets.ts"],'
        '"sourcesContent":["export const API_KEY = \\"sk_live_ABCDEFGHIJKLMNOPQRSTUVWX\\";"]}',
    ),
}


def _make_client(
    guard: ScopeGuard, calls: list[str], rate_limiter: RateLimiter | None = None
) -> GuardedHttpClient:
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        status, body = FIXTURE_RESPONSES.get(str(request.url), (404, "not found"))
        return httpx.Response(status, text=body)

    transport = httpx.MockTransport(handler)
    async_client = httpx.AsyncClient(transport=transport)
    return GuardedHttpClient(guard, client=async_client, rate_limiter=rate_limiter)


def _scope() -> ScopeConfig:
    return ScopeConfig(
        in_scope=[ScopeEntry(domain="example.com", match_type=MatchType.WILDCARD)],
        out_of_scope=["blog.example.com"],
    )


@pytest.mark.parametrize(
    "url,expected",
    [
        ("https://example.com/app.js", True),
        ("https://example.com/app.js?v=123", True),
        ("https://example.com/app.js#frag", True),
        ("https://example.com/app.json", False),
        ("https://example.com/page.html", False),
    ],
)
def test_looks_like_js(url: str, expected: bool) -> None:
    assert looks_like_js(url) is expected


def test_fetch_js_files_only_fetches_allowed_js_urls() -> None:
    guard = ScopeGuard(_scope())
    calls: list[str] = []
    client = _make_client(guard, calls)

    urls = [
        "https://api.example.com/app.js",
        "https://api.example.com/plain.json",  # not .js, should never be fetched
        "https://blog.example.com/evil.js",  # out of scope, ScopeGuard must deny it
    ]

    async def run() -> list:  # type: ignore[type-arg]
        try:
            return await fetch_js_files(urls, client)
        finally:
            await client.aclose()

    fetched = asyncio.run(run())

    assert len(fetched) == 1
    assert fetched[0].url == "https://api.example.com/app.js"
    assert "console.log" in fetched[0].content
    assert fetched[0].source_map_found is True
    assert fetched[0].source_map_url == "https://api.example.com/app.js.map"

    # the out-of-scope .js URL and the non-.js URL must never reach the network
    assert "https://blog.example.com/evil.js" not in calls
    assert "https://api.example.com/plain.json" not in calls


def test_fetch_js_files_recovers_source_map_content() -> None:
    guard = ScopeGuard(_scope())
    client = _make_client(guard, [])

    async def run() -> list:  # type: ignore[type-arg]
        try:
            return await fetch_js_files(["https://api.example.com/rich.js"], client)
        finally:
            await client.aclose()

    fetched = asyncio.run(run())

    assert len(fetched) == 2
    minified, recovered = fetched
    assert minified.recovered_from_source_map is False
    assert recovered.recovered_from_source_map is True
    assert "API_KEY" in recovered.content
    assert "src/secrets.ts" in recovered.url


def test_fetch_js_files_skips_non_200_responses() -> None:
    guard = ScopeGuard(_scope())
    client = _make_client(guard, [])

    async def run() -> list:  # type: ignore[type-arg]
        try:
            return await fetch_js_files(["https://api.example.com/broken.js"], client)
        finally:
            await client.aclose()

    assert asyncio.run(run()) == []


@pytest.mark.parametrize(
    "url,expected",
    [
        ("https://example.com/product?productId=1", True),
        ("https://example.com/my-account", True),
        ("https://example.com/app.js", False),  # already handled by fetch_js_files
        ("https://example.com/style.css", False),
        ("https://example.com/logo.png?v=2", False),
        ("https://example.com/font.woff2", False),
    ],
)
def test_looks_like_page(url: str, expected: bool) -> None:
    assert looks_like_page(url) is expected


def test_fetch_page_files_only_fetches_non_js_non_asset_urls() -> None:
    guard = ScopeGuard(_scope())
    calls: list[str] = []
    client = _make_client(guard, calls)

    urls = [
        "https://api.example.com/product",
        "https://api.example.com/app.js",  # JS, not a page
        "https://api.example.com/style.css",  # static asset, no recon value
        "https://blog.example.com/secret-page",  # out of scope, must be denied
    ]

    async def run() -> list:  # type: ignore[type-arg]
        try:
            return await fetch_page_files(urls, client)
        finally:
            await client.aclose()

    fetched = asyncio.run(run())

    assert len(fetched) == 1
    assert fetched[0].url == "https://api.example.com/product"
    assert "product page" in fetched[0].content

    assert "https://api.example.com/app.js" not in calls
    assert "https://api.example.com/style.css" not in calls


def test_fetch_page_files_captures_response_headers() -> None:
    guard = ScopeGuard(_scope())
    cors_headers = {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "true",
    }

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>page</html>", headers=cors_headers)

    client = GuardedHttpClient(
        guard, client=httpx.AsyncClient(transport=httpx.MockTransport(handler))
    )

    async def run() -> list:  # type: ignore[type-arg]
        try:
            return await fetch_page_files(["https://api.example.com/product"], client)
        finally:
            await client.aclose()

    fetched = asyncio.run(run())
    assert fetched[0].headers["access-control-allow-origin"] == "*"
    assert fetched[0].headers["access-control-allow-credentials"] == "true"


def test_get_text_returns_none_for_denied_url() -> None:
    guard = ScopeGuard(_scope())
    client = _make_client(guard, [])

    async def run() -> str | None:
        try:
            return await client.get_text("https://not-in-scope.com/app.js")
        finally:
            await client.aclose()

    assert asyncio.run(run()) is None


class RecordingLimiter(RateLimiter):
    def __init__(self) -> None:
        super().__init__(None)
        self.acquire_calls = 0

    async def acquire(self) -> None:
        self.acquire_calls += 1


def test_get_text_consults_the_rate_limiter_before_each_request() -> None:
    guard = ScopeGuard(_scope())
    limiter = RecordingLimiter()
    client = _make_client(guard, [], rate_limiter=limiter)

    async def run() -> None:
        await client.get_text("https://api.example.com/app.js")
        await client.get_text("https://api.example.com/app.js")

    try:
        asyncio.run(run())
    finally:
        asyncio.run(client.aclose())

    assert limiter.acquire_calls == 2


def test_get_text_does_not_consult_rate_limiter_for_denied_url() -> None:
    guard = ScopeGuard(_scope())
    limiter = RecordingLimiter()
    client = _make_client(guard, [], rate_limiter=limiter)

    async def run() -> str | None:
        return await client.get_text("https://not-in-scope.com/app.js")

    try:
        result = asyncio.run(run())
    finally:
        asyncio.run(client.aclose())

    assert result is None
    assert limiter.acquire_calls == 0


def test_get_text_forwards_extra_headers() -> None:
    guard = ScopeGuard(_scope())
    seen_headers: list[httpx.Headers] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_headers.append(request.headers)
        return httpx.Response(200, text="ok")

    client = GuardedHttpClient(
        guard, client=httpx.AsyncClient(transport=httpx.MockTransport(handler))
    )

    async def run() -> str | None:
        try:
            return await client.get_text(
                "https://api.example.com/app.js", extra_headers={"Cookie": "session=abc123"}
            )
        finally:
            await client.aclose()

    result = asyncio.run(run())
    assert result == "ok"
    assert seen_headers[0]["cookie"] == "session=abc123"


def test_get_text_without_extra_headers_sends_no_cookie() -> None:
    guard = ScopeGuard(_scope())
    seen_headers: list[httpx.Headers] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_headers.append(request.headers)
        return httpx.Response(200, text="ok")

    client = GuardedHttpClient(
        guard, client=httpx.AsyncClient(transport=httpx.MockTransport(handler))
    )

    async def run() -> str | None:
        try:
            return await client.get_text("https://api.example.com/app.js")
        finally:
            await client.aclose()

    asyncio.run(run())
    assert "cookie" not in seen_headers[0]


def test_get_text_with_headers_returns_body_and_lowercased_headers() -> None:
    guard = ScopeGuard(_scope())

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            text="ok",
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
            },
        )

    client = GuardedHttpClient(
        guard, client=httpx.AsyncClient(transport=httpx.MockTransport(handler))
    )

    async def run() -> tuple[str, dict[str, str]] | None:
        try:
            return await client.get_text_with_headers("https://api.example.com/app.js")
        finally:
            await client.aclose()

    result = asyncio.run(run())
    assert result is not None
    body, headers = result
    assert body == "ok"
    assert headers["access-control-allow-origin"] == "*"
    assert headers["access-control-allow-credentials"] == "true"


def test_get_text_with_headers_returns_none_for_denied_url() -> None:
    guard = ScopeGuard(_scope())
    client = _make_client(guard, [])

    async def run() -> tuple[str, dict[str, str]] | None:
        try:
            return await client.get_text_with_headers("https://blog.example.com/evil.js")
        finally:
            await client.aclose()

    assert asyncio.run(run()) is None
