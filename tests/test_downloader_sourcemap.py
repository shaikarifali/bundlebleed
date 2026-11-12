from __future__ import annotations

import json

from bundlebleed.downloader.sourcemap import parse_source_map

MAP_URL = "https://example.com/app.js.map"


def test_recovers_sources_with_content() -> None:
    map_content = json.dumps(
        {
            "version": 3,
            "sources": ["webpack:///./src/api.js", "webpack:///./src/secrets.js"],
            "sourcesContent": [
                "export function fetchUser(id) { return fetch(`/api/v1/users/${id}`); }",
                "export const API_KEY = 'sk_live_ABCDEFGHIJKLMNOPQRSTUVWX';",
            ],
        }
    )
    recovered = parse_source_map(map_content, MAP_URL)

    assert len(recovered) == 2
    assert all(f.recovered_from_source_map for f in recovered)
    assert "fetchUser" in recovered[0].content
    assert "API_KEY" in recovered[1].content
    assert "webpack:///./src/api.js" in recovered[0].url
    assert MAP_URL in recovered[0].url


def test_returns_empty_list_when_sources_content_is_absent() -> None:
    # Many real-world maps ship `sources` without embedded `sourcesContent`
    # to save space -- must degrade gracefully, not raise.
    map_content = json.dumps({"version": 3, "sources": ["app.ts"], "mappings": "AAAA"})
    assert parse_source_map(map_content, MAP_URL) == []


def test_returns_empty_list_on_malformed_json() -> None:
    assert parse_source_map("not json at all {{{", MAP_URL) == []


def test_returns_empty_list_when_top_level_is_not_an_object() -> None:
    assert parse_source_map("[1, 2, 3]", MAP_URL) == []


def test_skips_entries_with_null_or_empty_content() -> None:
    map_content = json.dumps(
        {
            "sources": ["a.js", "b.js", "c.js"],
            "sourcesContent": ["real content here", None, ""],
        }
    )
    recovered = parse_source_map(map_content, MAP_URL)
    assert len(recovered) == 1
    assert recovered[0].content == "real content here"


def test_mismatched_array_lengths_only_pairs_up_to_shortest() -> None:
    map_content = json.dumps({"sources": ["a.js", "b.js"], "sourcesContent": ["only one content"]})
    recovered = parse_source_map(map_content, MAP_URL)
    assert len(recovered) == 1
