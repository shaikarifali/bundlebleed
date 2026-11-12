from __future__ import annotations

from bundlebleed.processors.beautifier import beautify
from bundlebleed.processors.framework_detect import detect_frameworks
from tests.conftest import FIXTURES_DIR

REACT_FIXTURE = (FIXTURES_DIR / "js" / "framework_react.js").read_text()
NEXT_FIXTURE = (FIXTURES_DIR / "js" / "framework_next.js").read_text()
CLEAN_BUNDLE = (FIXTURES_DIR / "js" / "clean_bundle.js").read_text()


def test_beautify_expands_minified_code() -> None:
    minified = "function e(t){return t+1}"
    result = beautify(minified)
    assert "\n" in result
    assert "function e(t)" in result


def test_beautify_degrades_gracefully_on_malformed_input() -> None:
    malformed = "function( { [[[ unterminated"
    result = beautify(malformed)
    assert isinstance(result, str)


def test_detect_frameworks_react() -> None:
    assert detect_frameworks(REACT_FIXTURE) == ["react"]


def test_detect_frameworks_nextjs() -> None:
    assert detect_frameworks(NEXT_FIXTURE) == ["nextjs"]


def test_detect_frameworks_clean_bundle_finds_nothing() -> None:
    assert detect_frameworks(CLEAN_BUNDLE) == []
