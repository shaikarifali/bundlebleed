from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

import bundlebleed.collectors.waymore as waymore_module
from bundlebleed.collectors.waymore import WaymoreCollector


def test_collect_passes_url_only_mode_and_a_file_output_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    async def fake_run_subprocess_capturing_file(
        name: str, *args: str, domain: str, output_path: Path
    ) -> list[str]:
        captured["args"] = args
        captured["domain"] = domain
        captured["output_path"] = output_path
        return []

    monkeypatch.setattr(
        waymore_module, "run_subprocess_capturing_file", fake_run_subprocess_capturing_file
    )

    asyncio.run(WaymoreCollector().collect("example.com", []))

    args = captured["args"]
    assert args[:5] == ("waymore", "-i", "example.com", "-mode", "U")
    assert args[5] == "-oU"
    assert captured["domain"] == "example.com"
    assert isinstance(captured["output_path"], Path)
    assert str(captured["output_path"]) == args[6]


def test_collect_returns_whatever_the_helper_reads_back(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_run_subprocess_capturing_file(
        name: str, *args: str, domain: str, output_path: Path
    ) -> list[str]:
        return ["https://example.com/a.js", "https://example.com/b.js"]

    monkeypatch.setattr(
        waymore_module, "run_subprocess_capturing_file", fake_run_subprocess_capturing_file
    )

    result = asyncio.run(WaymoreCollector().collect("example.com", []))

    assert result == ["https://example.com/a.js", "https://example.com/b.js"]
