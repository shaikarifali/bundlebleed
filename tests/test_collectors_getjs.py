from __future__ import annotations

import asyncio

import bundlebleed.collectors.getjs as getjs_mod
from bundlebleed.collectors.getjs import GetJSCollector


def test_collector_name() -> None:
    assert GetJSCollector().name == "getjs"


def test_missing_binary_returns_empty(monkeypatch: object) -> None:
    async def _fake(*args: object, **kwargs: object) -> list[str]:
        return []

    monkeypatch.setattr(getjs_mod, "run_subprocess_lines", _fake)  # type: ignore[attr-defined]
    result = asyncio.run(GetJSCollector().collect("example.com", []))
    assert result == []


def test_uses_seed_url_when_given(monkeypatch: object) -> None:
    captured: list[str] = []

    async def _fake(*args: object, **kwargs: object) -> list[str]:
        captured.extend(str(a) for a in args)
        return []

    monkeypatch.setattr(getjs_mod, "run_subprocess_lines", _fake)  # type: ignore[attr-defined]
    asyncio.run(GetJSCollector().collect("example.com", ["https://example.com/app"]))
    assert "https://example.com/app" in captured


def test_falls_back_to_domain_when_no_seed(monkeypatch: object) -> None:
    captured: list[str] = []

    async def _fake(*args: object, **kwargs: object) -> list[str]:
        captured.extend(str(a) for a in args)
        return []

    monkeypatch.setattr(getjs_mod, "run_subprocess_lines", _fake)  # type: ignore[attr-defined]
    asyncio.run(GetJSCollector().collect("example.com", []))
    assert "https://example.com" in captured
