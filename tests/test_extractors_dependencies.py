from __future__ import annotations

import asyncio
import json

from bundlebleed.extractors.dependencies import _regex_fallback, extract_dependencies


def test_regex_fallback_jquery_old() -> None:
    content = "/*! jQuery v1.11.3 | (c) jQuery Foundation */"
    results = _regex_fallback(content, "/tmp/jquery.js")
    assert len(results) >= 1
    assert results[0].name == "jquery"
    assert results[0].version == "1.11.3"
    assert results[0].cves != []


def test_regex_fallback_no_match() -> None:
    content = "const x = 1; // no library"
    results = _regex_fallback(content, "/tmp/app.js")
    assert results == []


def test_regex_fallback_lodash() -> None:
    content = "// lodash 4.17.4"
    results = _regex_fallback(content, "/tmp/lodash.js")
    assert any(r.name == "lodash" for r in results)


def test_fallback_used_when_retire_missing(monkeypatch: object) -> None:
    import shutil

    monkeypatch.setattr(shutil, "which", lambda _: None)  # type: ignore[attr-defined]
    file_contents = [("/tmp/jquery.js", "/*! jQuery v1.4.0 */")]
    results = asyncio.run(extract_dependencies("/tmp/beautified", file_contents))
    assert any(r.name == "jquery" for r in results)


def test_retire_output_parsed(monkeypatch: object) -> None:
    import shutil

    monkeypatch.setattr(shutil, "which", lambda _: "retire")  # type: ignore[attr-defined]

    retire_data = {
        "data": [
            {
                "file": "/tmp/jquery.js",
                "results": [
                    {
                        "component": "jquery",
                        "version": "1.11.3",
                        "vulnerabilities": [
                            {"identifiers": {"CVE": ["CVE-2019-11358"]}}
                        ],
                    }
                ],
            }
        ]
    }

    class FakeProc:
        returncode = 0

        async def communicate(self) -> tuple[bytes, bytes]:
            return json.dumps(retire_data).encode(), b""

    import bundlebleed.extractors.dependencies as dep_mod

    async def fake_exec(*args: object, **kwargs: object) -> FakeProc:
        return FakeProc()

    monkeypatch.setattr(dep_mod.asyncio, "create_subprocess_exec", fake_exec)  # type: ignore[attr-defined]
    results = asyncio.run(extract_dependencies("/tmp/beautified", []))
    assert any("CVE-2019-11358" in r.cves for r in results)
