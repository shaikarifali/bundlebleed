from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TypeVar

from pydantic import BaseModel

T = TypeVar("T", bound=BaseModel)


class LLMProvider(ABC):
    """A pinned model, wrapped behind one structured-output call.

    The model string is supplied by the caller and never chosen or
    defaulted here — CLAUDE.md Invariant 8 requires every model to be an
    explicit, tracked choice; changing it is a change to detection logic.
    """

    def __init__(self, model: str) -> None:
        self.model = model

    @abstractmethod
    async def complete_structured(self, system: str, user: str, output_schema: type[T]) -> T:
        """Send one request and return a validated instance of `output_schema`."""
        ...
