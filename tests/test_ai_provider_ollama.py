from __future__ import annotations

import asyncio
import json

import httpx
import pytest
from pydantic import BaseModel

from bundlebleed.ai.providers.ollama import AIProviderError, OllamaProvider


class _Sample(BaseModel):
    value: str


def _client(handler: object) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))  # type: ignore[arg-type]


def test_complete_structured_returns_parsed_output_and_hits_expected_endpoint() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"message": {"content": '{"value": "hello"}'}})

    client = _client(handler)
    provider = OllamaProvider(model="llama3", host="http://localhost:11434", client=client)

    result = asyncio.run(provider.complete_structured("sys", "user", _Sample))

    assert result == _Sample(value="hello")
    assert len(requests) == 1
    assert requests[0].url == "http://localhost:11434/api/chat"
    body = json.loads(requests[0].content)
    assert body["model"] == "llama3"
    assert body["messages"] == [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "user"},
    ]
    assert body["format"] == _Sample.model_json_schema()
    assert body["stream"] is False


def test_strips_trailing_slash_from_host() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"message": {"content": '{"value": "x"}'}})

    client = _client(handler)
    provider = OllamaProvider(model="llama3", host="http://localhost:11434/", client=client)

    result = asyncio.run(provider.complete_structured("sys", "user", _Sample))
    assert result == _Sample(value="x")


def test_raises_on_non_200() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, text="model not found")

    client = _client(handler)
    provider = OllamaProvider(model="missing-model", host="http://localhost:11434", client=client)

    with pytest.raises(AIProviderError, match="404"):
        asyncio.run(provider.complete_structured("sys", "user", _Sample))


def test_raises_when_content_missing() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"message": {}})

    client = _client(handler)
    provider = OllamaProvider(model="llama3", host="http://localhost:11434", client=client)

    with pytest.raises(AIProviderError, match="no message content"):
        asyncio.run(provider.complete_structured("sys", "user", _Sample))


def test_raises_when_content_does_not_match_schema() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"message": {"content": '{"wrong_field": 1}'}})

    client = _client(handler)
    provider = OllamaProvider(model="llama3", host="http://localhost:11434", client=client)

    with pytest.raises(AIProviderError, match="did not match the expected schema"):
        asyncio.run(provider.complete_structured("sys", "user", _Sample))


def test_raises_when_content_is_not_valid_json() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"message": {"content": "not json at all"}})

    client = _client(handler)
    provider = OllamaProvider(model="llama3", host="http://localhost:11434", client=client)

    with pytest.raises(AIProviderError, match="did not match the expected schema"):
        asyncio.run(provider.complete_structured("sys", "user", _Sample))


def test_never_picks_a_default_model() -> None:
    """Invariant 8: models are pinned by the caller, never chosen here."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"message": {"content": '{"value": "x"}'}})

    client = _client(handler)
    provider = OllamaProvider(model="explicitly-pinned-model", host="http://x", client=client)
    assert provider.model == "explicitly-pinned-model"
