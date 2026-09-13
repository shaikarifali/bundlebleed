from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

import pytest
from pydantic import BaseModel

from bundlebleed.ai.providers.anthropic import AIProviderError, AnthropicProvider


class _Sample(BaseModel):
    value: str


@dataclass
class _FakeStopDetails:
    category: str | None


@dataclass
class _FakeResponse:
    stop_reason: str
    parsed_output: Any = None
    stop_details: _FakeStopDetails | None = None


class _FakeMessagesResource:
    def __init__(self, response: _FakeResponse) -> None:
        self._response = response
        self.calls: list[dict[str, Any]] = []

    async def parse(self, **kwargs: Any) -> _FakeResponse:
        self.calls.append(kwargs)
        return self._response


class _FakeAnthropicClient:
    def __init__(self, response: _FakeResponse) -> None:
        self.messages = _FakeMessagesResource(response)


def test_complete_structured_returns_parsed_output() -> None:
    response = _FakeResponse(stop_reason="end_turn", parsed_output=_Sample(value="hello"))
    client = _FakeAnthropicClient(response)
    provider = AnthropicProvider(model="claude-fake-1", client=client)  # type: ignore[arg-type]

    result = asyncio.run(provider.complete_structured("sys", "user", _Sample))

    assert result == _Sample(value="hello")
    assert client.messages.calls[0]["model"] == "claude-fake-1"
    assert client.messages.calls[0]["system"] == "sys"
    assert client.messages.calls[0]["output_format"] is _Sample


def test_complete_structured_raises_on_refusal() -> None:
    response = _FakeResponse(stop_reason="refusal", stop_details=_FakeStopDetails(category="cyber"))
    client = _FakeAnthropicClient(response)
    provider = AnthropicProvider(model="claude-fake-1", client=client)  # type: ignore[arg-type]

    with pytest.raises(AIProviderError, match="refused"):
        asyncio.run(provider.complete_structured("sys", "user", _Sample))


def test_complete_structured_raises_when_parsed_output_is_none() -> None:
    response = _FakeResponse(stop_reason="max_tokens", parsed_output=None)
    client = _FakeAnthropicClient(response)
    provider = AnthropicProvider(model="claude-fake-1", client=client)  # type: ignore[arg-type]

    with pytest.raises(AIProviderError, match="did not return a parseable"):
        asyncio.run(provider.complete_structured("sys", "user", _Sample))


def test_never_picks_a_default_model() -> None:
    """Invariant 8: models are pinned by the caller, never chosen here."""
    response = _FakeResponse(stop_reason="end_turn", parsed_output=_Sample(value="x"))
    client = _FakeAnthropicClient(response)
    provider = AnthropicProvider(model="explicitly-pinned-model", client=client)  # type: ignore[arg-type]
    assert provider.model == "explicitly-pinned-model"
