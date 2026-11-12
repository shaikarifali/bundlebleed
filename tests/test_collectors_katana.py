from __future__ import annotations

import asyncio

import pytest

import bundlebleed.collectors.katana as katana_module
from bundlebleed.collectors.katana import KatanaCollector


def test_collect_passes_bare_domain_with_no_seed_urls(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, tuple[str, ...]] = {}

    async def fake_run_subprocess_lines(name: str, *args: str, domain: str) -> list[str]:
        captured["args"] = args
        return []

    monkeypatch.setattr(katana_module, "run_subprocess_lines", fake_run_subprocess_lines)

    asyncio.run(KatanaCollector().collect("example.com", []))

    assert captured["args"] == ("katana", "-u", "example.com", "-silent", "-jc")


def test_collect_adds_each_seed_url_as_an_additional_crawl_start(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, tuple[str, ...]] = {}

    async def fake_run_subprocess_lines(name: str, *args: str, domain: str) -> list[str]:
        captured["args"] = args
        return []

    monkeypatch.setattr(katana_module, "run_subprocess_lines", fake_run_subprocess_lines)

    asyncio.run(
        KatanaCollector().collect(
            "example.com",
            ["https://example.com/app", "https://example.com/legacy-portal"],
        )
    )

    assert captured["args"] == (
        "katana",
        "-u",
        "example.com",
        "-u",
        "https://example.com/app",
        "-u",
        "https://example.com/legacy-portal",
        "-silent",
        "-jc",
    )
