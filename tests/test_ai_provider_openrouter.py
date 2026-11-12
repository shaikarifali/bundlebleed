from __future__ import annotations

import asyncio
import json

import httpx
import pytest
from pydantic import BaseModel

from bundlebleed.ai.providers.openrouter import AIProviderError, OpenRouterProvider


class _Sample(BaseModel):
    value: str


def _client(handler: object) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))  # type: ignore[arg-type]


def _chat_response(content: str) -> httpx.Response:
    return httpx.Response(200, json={"choices": [{"message": {"content": content}}]})


def test_complete_structured_returns_parsed_output_and_hits_expected_endpoint() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return _chat_response('{"value": "hello"}')

    client = _client(handler)
    provider = OpenRouterProvider(model="some/model:free", api_key="sk-or-test", client=client)

    result = asyncio.run(provider.complete_structured("sys", "user", _Sample))

    assert result == _Sample(value="hello")
    assert len(requests) == 1
    assert requests[0].url == "https://openrouter.ai/api/v1/chat/completions"
    assert requests[0].headers["authorization"] == "Bearer sk-or-test"
    body = json.loads(requests[0].content)
    assert body["model"] == "some/model:free"
    assert body["messages"] == [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "user"},
    ]
    assert body["response_format"]["type"] == "json_schema"
    assert body["response_format"]["json_schema"]["schema"] == _Sample.model_json_schema()
    assert body["response_format"]["json_schema"]["strict"] is True


def test_raises_on_non_200() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, text="invalid api key")

    client = _client(handler)
    provider = OpenRouterProvider(model="some/model:free", api_key="bad-key", client=client)

    with pytest.raises(AIProviderError, match="401"):
        asyncio.run(provider.complete_structured("sys", "user", _Sample))


def test_raises_when_no_choices() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"choices": []})

    client = _client(handler)
    provider = OpenRouterProvider(model="some/model:free", api_key="sk-or-test", client=client)

    with pytest.raises(AIProviderError, match="no choices"):
        asyncio.run(provider.complete_structured("sys", "user", _Sample))


def test_raises_when_content_missing() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"choices": [{"message": {}}]})

    client = _client(handler)
    provider = OpenRouterProvider(model="some/model:free", api_key="sk-or-test", client=client)

    with pytest.raises(AIProviderError, match="no message content"):
        asyncio.run(provider.complete_structured("sys", "user", _Sample))


def test_raises_when_content_does_not_match_schema() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return _chat_response('{"wrong_field": 1}')

    client = _client(handler)
    provider = OpenRouterProvider(model="some/model:free", api_key="sk-or-test", client=client)

    with pytest.raises(AIProviderError, match="did not match the expected schema"):
        asyncio.run(provider.complete_structured("sys", "user", _Sample))


def test_raises_when_content_is_not_valid_json() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return _chat_response("not json at all")

    client = _client(handler)
    provider = OpenRouterProvider(model="some/model:free", api_key="sk-or-test", client=client)

    with pytest.raises(AIProviderError, match="did not match the expected schema"):
        asyncio.run(provider.complete_structured("sys", "user", _Sample))


def test_never_hardcodes_an_api_key_or_model() -> None:
    """Invariant 8 (models pinned) and the "no key in code" rule both apply here."""

    def handler(request: httpx.Request) -> httpx.Response:
        return _chat_response('{"value": "x"}')

    client = _client(handler)
    provider = OpenRouterProvider(
        model="explicitly-pinned-model", api_key="explicit-key", client=client
    )
    assert provider.model == "explicitly-pinned-model"
    assert provider._api_key == "explicit-key"
