from __future__ import annotations

from pydantic import BaseModel, Field


class RuntimeEvent(BaseModel):
    url: str
    method: str
    resource_type: str
    allowed: bool


class RuntimeCapture(BaseModel):
    page_url: str
    events: list[RuntimeEvent] = Field(default_factory=list)
    discovered_js_urls: list[str] = Field(default_factory=list)
