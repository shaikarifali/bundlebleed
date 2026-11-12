from __future__ import annotations

import json
from typing import TypeVar

import httpx
from pydantic import BaseModel, ValidationError

from bundlebleed.ai.providers.base import LLMProvider

T = TypeVar("T", bound=BaseModel)


class AIProviderError(RuntimeError):
    pass


class OllamaProvider(LLMProvider):
    """Wraps Ollama's `/api/chat` structured-outputs contract for one-shot
    structured-output calls against a locally (or LAN-)hosted model.

    `host` is a required argument, never guessed or defaulted — a wrong or
    unreachable host should fail loudly and immediately, not hang or
    silently fall back to some assumed address.
    """

    def __init__(
        self,
        model: str,
        host: str,
        client: httpx.AsyncClient | None = None,
        timeout: float = 120.0,
    ) -> None:
        super().__init__(model)
        self._host = host.rstrip("/")
        self._client = client or httpx.AsyncClient(timeout=timeout)
        self._owns_client = client is None

    async def complete_structured(self, system: str, user: str, output_schema: type[T]) -> T:
        try:
            response = await self._client.post(
                f"{self._host}/api/chat",
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                    "format": output_schema.model_json_schema(),
                    "stream": False,
                },
            )
        except httpx.HTTPError as exc:
            raise AIProviderError(f"could not reach Ollama at {self._host}: {exc}") from exc

        if response.status_code != 200:
            raise AIProviderError(
                f"Ollama returned HTTP {response.status_code}: {response.text[:200]}"
            )

        try:
            body = response.json()
        except json.JSONDecodeError as exc:
            raise AIProviderError(f"Ollama response was not valid JSON: {exc}") from exc

        content = body.get("message", {}).get("content")
        if not content:
            raise AIProviderError("Ollama response had no message content")

        try:
            return output_schema.model_validate_json(content)
        except ValidationError as exc:
            raise AIProviderError(f"model output did not match the expected schema: {exc}") from exc

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()
