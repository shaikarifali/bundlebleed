from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

import bundlebleed.collectors.paramspider as paramspider_module
from bundlebleed.collectors.paramspider import ParamSpiderCollector


def test_collect_passes_domain_and_a_file_output_path(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    async def fake_run_subprocess_capturing_file(
        name: str, *args: str, domain: str, output_path: Path
    ) -> list[str]:
        captured["args"] = args
        captured["domain"] = domain
        captured["output_path"] = output_path
        return []

    monkeypatch.setattr(
        paramspider_module, "run_subprocess_capturing_file", fake_run_subprocess_capturing_file
    )

    asyncio.run(ParamSpiderCollector().collect("example.com", []))

    args = captured["args"]
    assert args[:3] == ("paramspider", "-d", "example.com")
    assert args[3] == "-o"
    assert captured["domain"] == "example.com"
    assert isinstance(captured["output_path"], Path)
    assert str(captured["output_path"]) == args[4]


def test_collect_returns_whatever_the_helper_reads_back(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_run_subprocess_capturing_file(
        name: str, *args: str, domain: str, output_path: Path
    ) -> list[str]:
        return ["https://example.com/page?token=abc", "https://example.com/page?id=1"]

    monkeypatch.setattr(
        paramspider_module, "run_subprocess_capturing_file", fake_run_subprocess_capturing_file
    )

    result = asyncio.run(ParamSpiderCollector().collect("example.com", []))

    assert result == ["https://example.com/page?token=abc", "https://example.com/page?id=1"]
