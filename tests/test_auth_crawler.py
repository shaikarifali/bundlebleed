from __future__ import annotations

import asyncio
import logging

import httpx
import pytest
import structlog

from bundlebleed.auth.crawler import fetch_authenticated_script_urls
from bundlebleed.auth.models import AuthSession
from bundlebleed.downloader.http_client import GuardedHttpClient
from bundlebleed.scope.guard import ScopeGuard
from bundlebleed.scope.models import MatchType, ScopeConfig, ScopeEntry

SECRET_COOKIE_VALUE = "session=TOP-SECRET-DO-NOT-LEAK-abc123xyz"

HTML_PAGE = """
<html><body>
  <script src="/static/app.js"></script>
  <script src="/admin/panel.js"></script>
</body></html>
"""


def _scope() -> ScopeConfig:
    return ScopeConfig(
        in_scope=[ScopeEntry(domain="example.com", match_type=MatchType.WILDCARD)],
        out_of_scope=["blog.example.com"],
    )


def _make_client(guard: ScopeGuard, seen_headers: list[httpx.Headers]) -> GuardedHttpClient:
    def handler(request: httpx.Request) -> httpx.Response:
        seen_headers.append(request.headers)
        return httpx.Response(200, text=HTML_PAGE)

    transport = httpx.MockTransport(handler)
    return GuardedHttpClient(guard, client=httpx.AsyncClient(transport=transport))


def test_authenticated_crawl_attaches_cookie_header() -> None:
    guard = ScopeGuard(_scope())
    seen_headers: list[httpx.Headers] = []
    client = _make_client(guard, seen_headers)
    session = AuthSession(name="user", role="user", cookie_header=SECRET_COOKIE_VALUE)

    async def run() -> list[str]:
        try:
            return await fetch_authenticated_script_urls(
                ["https://example.com/dashboard"], session, client
            )
        finally:
            await client.aclose()

    urls = asyncio.run(run())

    assert "https://example.com/static/app.js" in urls
    assert "https://example.com/admin/panel.js" in urls
    assert seen_headers[0]["cookie"] == SECRET_COOKIE_VALUE


def test_authenticated_crawl_never_fetches_out_of_scope_pages() -> None:
    guard = ScopeGuard(_scope())
    seen_headers: list[httpx.Headers] = []
    client = _make_client(guard, seen_headers)
    session = AuthSession(name="user", role="user", cookie_header=SECRET_COOKIE_VALUE)

    async def run() -> list[str]:
        try:
            return await fetch_authenticated_script_urls(
                ["https://blog.example.com/dashboard"], session, client
            )
        finally:
            await client.aclose()

    urls = asyncio.run(run())

    assert urls == []
    assert seen_headers == []  # cookie was never even sent for the out-of-scope page


def test_cookie_value_never_appears_in_captured_logs(capsys: pytest.CaptureFixture[str]) -> None:
    structlog.configure(
        processors=[structlog.processors.JSONRenderer()],
        wrapper_class=structlog.make_filtering_bound_logger(logging.DEBUG),
        logger_factory=structlog.PrintLoggerFactory(),
    )

    guard = ScopeGuard(_scope())
    seen_headers: list[httpx.Headers] = []
    client = _make_client(guard, seen_headers)
    session = AuthSession(name="user", role="user", cookie_header=SECRET_COOKIE_VALUE)

    async def run() -> None:
        try:
            await fetch_authenticated_script_urls(
                ["https://example.com/dashboard", "https://not-in-scope.com/x"], session, client
            )
        finally:
            await client.aclose()

    asyncio.run(run())

    captured = capsys.readouterr()
    assert SECRET_COOKIE_VALUE not in captured.out
    assert SECRET_COOKIE_VALUE not in captured.err


def test_cookie_value_never_appears_in_scope_guard_audit_log(tmp_path) -> None:  # type: ignore[no-untyped-def]
    audit_path = tmp_path / "audit_log.jsonl"
    guard = ScopeGuard(_scope(), audit_log_path=audit_path, scan_run_id="run-1")
    seen_headers: list[httpx.Headers] = []
    client = _make_client(guard, seen_headers)
    session = AuthSession(name="user", role="user", cookie_header=SECRET_COOKIE_VALUE)

    async def run() -> None:
        try:
            await fetch_authenticated_script_urls(
                ["https://example.com/dashboard"], session, client
            )
        finally:
            await client.aclose()

    asyncio.run(run())

    audit_content = audit_path.read_text()
    assert SECRET_COOKIE_VALUE not in audit_content


def test_authenticated_crawl_deduplicates_across_pages() -> None:
    guard = ScopeGuard(_scope())
    seen_headers: list[httpx.Headers] = []
    client = _make_client(guard, seen_headers)
    session = AuthSession(name="user", role="user", cookie_header=SECRET_COOKIE_VALUE)

    async def run() -> list[str]:
        try:
            return await fetch_authenticated_script_urls(
                ["https://example.com/a", "https://example.com/b"], session, client
            )
        finally:
            await client.aclose()

    urls = asyncio.run(run())
    assert len(urls) == len(set(urls))
