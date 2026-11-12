from __future__ import annotations

import asyncio

import httpx

from bundlebleed.monitoring.webhook import post_webhook


def _client(status_code: int) -> httpx.AsyncClient:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code, json={"ok": status_code < 300})

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def test_post_webhook_returns_true_on_2xx() -> None:
    client = _client(200)

    async def run() -> bool:
        try:
            return await post_webhook("https://hooks.example.com/x", {"text": "hi"}, client)
        finally:
            await client.aclose()

    assert asyncio.run(run()) is True


def test_post_webhook_returns_false_on_non_2xx() -> None:
    client = _client(500)

    async def run() -> bool:
        try:
            return await post_webhook("https://hooks.example.com/x", {"text": "hi"}, client)
        finally:
            await client.aclose()

    assert asyncio.run(run()) is False


def test_post_webhook_sends_the_given_payload() -> None:
    captured: list[bytes] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request.content)
        return httpx.Response(200)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))

    async def run() -> bool:
        try:
            return await post_webhook(
                "https://hooks.example.com/x", {"text": "hello world"}, client
            )
        finally:
            await client.aclose()

    asyncio.run(run())
    assert b"hello world" in captured[0]


def test_post_webhook_never_raises_on_connection_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom", request=request)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))

    async def run() -> bool:
        try:
            return await post_webhook("https://hooks.example.com/x", {"text": "hi"}, client)
        finally:
            await client.aclose()

    assert asyncio.run(run()) is False
