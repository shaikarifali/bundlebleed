from __future__ import annotations

import json
from typing import TypeVar

import httpx
from pydantic import BaseModel, ValidationError

from bundlebleed.ai.providers.base import LLMProvider

T = TypeVar("T", bound=BaseModel)


class AIProviderError(RuntimeError):
    pass


class OpenRouterProvider(LLMProvider):
    """Wraps OpenRouter's OpenAI-compatible `/chat/completions` endpoint for
    one-shot structured-output calls.

    OpenRouter fronts many models (including several free, rate-limited ones
    tagged `:free`) behind one API key — useful for testing without an
    Anthropic key or a local Ollama install. The key is passed in explicitly
    by the caller (the CLI reads it from an env var); never hardcoded or
    silently defaulted here.
    """

    _BASE_URL = "https://openrouter.ai/api/v1"

    def __init__(
        self,
        model: str,
        api_key: str,
        client: httpx.AsyncClient | None = None,
        timeout: float = 120.0,
    ) -> None:
        super().__init__(model)
        self._api_key = api_key
        self._client = client or httpx.AsyncClient(timeout=timeout)
        self._owns_client = client is None

    async def complete_structured(self, system: str, user: str, output_schema: type[T]) -> T:
        try:
            response = await self._client.post(
                f"{self._BASE_URL}/chat/completions",
                headers={"Authorization": f"Bearer {self._api_key}"},
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                    "response_format": {
                        "type": "json_schema",
                        "json_schema": {
                            "name": output_schema.__name__,
                            "schema": output_schema.model_json_schema(),
                            "strict": True,
                        },
                    },
                },
            )
        except httpx.HTTPError as exc:
            raise AIProviderError(f"could not reach OpenRouter: {exc}") from exc

        if response.status_code != 200:
            raise AIProviderError(
                f"OpenRouter returned HTTP {response.status_code}: {response.text[:200]}"
            )

        try:
            body = response.json()
        except json.JSONDecodeError as exc:
            raise AIProviderError(f"OpenRouter response was not valid JSON: {exc}") from exc

        choices = body.get("choices") or []
        if not choices:
            raise AIProviderError(f"OpenRouter response had no choices: {str(body)[:200]}")

        content = choices[0].get("message", {}).get("content")
        if not content:
            raise AIProviderError("OpenRouter response had no message content")

        try:
            return output_schema.model_validate_json(content)
        except ValidationError as exc:
            raise AIProviderError(f"model output did not match the expected schema: {exc}") from exc

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()
