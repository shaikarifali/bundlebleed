from __future__ import annotations

from typing import TypeVar

import anthropic
from pydantic import BaseModel

from bundlebleed.ai.providers.base import LLMProvider

T = TypeVar("T", bound=BaseModel)


class AIProviderError(RuntimeError):
    pass


class AnthropicProvider(LLMProvider):
    """Wraps `anthropic.AsyncAnthropic` for one-shot structured-output calls.

    Reads credentials the SDK's normal way (ANTHROPIC_API_KEY env var by
    default) — never accepts or stores an API key in config, per the plan's
    "never store API keys in config files" rule.
    """

    def __init__(
        self,
        model: str,
        client: anthropic.AsyncAnthropic | None = None,
        max_tokens: int = 4096,
    ) -> None:
        super().__init__(model)
        self._client = client or anthropic.AsyncAnthropic()
        self._max_tokens = max_tokens

    async def complete_structured(self, system: str, user: str, output_schema: type[T]) -> T:
        response = await self._client.messages.parse(
            model=self.model,
            max_tokens=self._max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
            output_format=output_schema,
        )

        if response.stop_reason == "refusal":
            category = getattr(response.stop_details, "category", None)
            raise AIProviderError(f"model refused the request (category={category})")

        if response.parsed_output is None:
            raise AIProviderError(
                f"model did not return a parseable structured output "
                f"(stop_reason={response.stop_reason!r})"
            )

        return response.parsed_output
