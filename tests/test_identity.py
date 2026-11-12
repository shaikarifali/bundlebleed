from __future__ import annotations

from bundlebleed.identity import endpoint_id, stable_id
from bundlebleed.models import Endpoint


def test_stable_id_is_deterministic() -> None:
    assert stable_id("a", "b", "c") == stable_id("a", "b", "c")


def test_stable_id_distinguishes_part_boundaries() -> None:
    # "ab", "c" vs "a", "bc" must not collide just because concatenation matches
    assert stable_id("ab", "c") != stable_id("a", "bc")


def test_endpoint_id_matches_manual_stable_id() -> None:
    endpoint = Endpoint(value="/api/v1/x", pattern_name="rest_api_path", source_url="https://e.com")
    assert endpoint_id(endpoint) == stable_id("rest_api_path", "/api/v1/x", "https://e.com")
