from __future__ import annotations

import asyncio

import bundlebleed.collectors.waymore as waymore_mod
from bundlebleed.collectors.waymore import WaymoreCollector


def test_collector_name() -> None:
    assert WaymoreCollector().name == "waymore"


def test_missing_binary_returns_empty(monkeypatch: object) -> None:
    async def _fake(*args: object, **kwargs: object) -> list[str]:
        return []

    monkeypatch.setattr(waymore_mod, "run_subprocess_lines", _fake)  # type: ignore[attr-defined]
    result = asyncio.run(WaymoreCollector().collect("example.com", []))
    assert result == []


def test_collect_returns_lines(monkeypatch: object) -> None:
    async def _fake(*args: object, **kwargs: object) -> list[str]:
        return ["https://example.com/old.js", "https://example.com/archive.js"]

    monkeypatch.setattr(waymore_mod, "run_subprocess_lines", _fake)  # type: ignore[attr-defined]
    result = asyncio.run(WaymoreCollector().collect("example.com", []))
    assert len(result) == 2
