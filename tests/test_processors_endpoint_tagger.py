from __future__ import annotations

from bundlebleed.models import Endpoint
from bundlebleed.processors.endpoint_tagger import tag_endpoints


def _ep(value: str, source_url: str = "https://example.com/app.js") -> Endpoint:
    return Endpoint(value=value, pattern_name="url_path", source_url=source_url)


def test_live_endpoint_tagged_live() -> None:
    ep = _ep("/api/users")
    collected = ["https://example.com/api/users"]
    tagged = tag_endpoints([ep], collected, set(), [], [])
    assert tagged[0].tag == "live"


def test_historical_endpoint_tagged() -> None:
    ep = _ep("/api/v1/old-endpoint")
    tagged = tag_endpoints([ep], [], {"/api/v1/old-endpoint"}, [], [])
    assert tagged[0].tag == "historical"


def test_auth_required_endpoint_tagged() -> None:
    ep = _ep("/api/admin", source_url="https://example.com/admin.js")
    tagged = tag_endpoints(
        [ep],
        ["https://example.com/api/admin"],
        set(),
        ["https://example.com/admin.js"],
        [],
    )
    assert tagged[0].tag == "auth-required"


def test_runtime_confirmed_endpoint_tagged_live() -> None:
    ep = _ep("/api/profile")
    tagged = tag_endpoints([ep], [], set(), [], ["/api/profile"])
    assert tagged[0].tag == "live"


def test_not_in_live_crawl_tagged_historical() -> None:
    ep = _ep("/api/secret-path")
    tagged = tag_endpoints([ep], ["https://example.com/other"], set(), [], [])
    assert tagged[0].tag == "historical"


def test_empty_input() -> None:
    assert tag_endpoints([], [], set(), [], []) == []


def test_original_model_not_mutated() -> None:
    ep = _ep("/api/users")
    original_tag = ep.tag
    tag_endpoints([ep], [], set(), [], [])
    assert ep.tag == original_tag
