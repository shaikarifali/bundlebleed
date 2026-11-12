from __future__ import annotations

from bundlebleed.models import Endpoint
from bundlebleed.processors.endpoint_tagger import tag_endpoints


def _ep(value: str, source_url: str) -> Endpoint:
    return Endpoint(value=value, pattern_name="url_path", source_url=source_url)


def test_prod_environment_tagged() -> None:
    ep = _ep("/api/users", "https://example.com/app.js")
    tagged = tag_endpoints([ep], ["https://example.com/api/users"], set(), [], [])
    assert tagged[0].environment == "prod"


def test_staging_environment_tagged() -> None:
    ep = _ep("/api/users", "https://staging.example.com/app.js")
    tagged = tag_endpoints([ep], [], set(), [], [])
    assert tagged[0].environment == "staging"


def test_staging_subdomain_prefix() -> None:
    ep = _ep("/api/data", "https://app.stg.example.com/app.js")
    tagged = tag_endpoints([ep], [], set(), [], [])
    assert tagged[0].environment == "staging"


def test_dev_environment_tagged() -> None:
    ep = _ep("/api/users", "https://dev.example.com/app.js")
    tagged = tag_endpoints([ep], [], set(), [], [])
    assert tagged[0].environment == "dev"


def test_sandbox_environment_tagged_as_staging() -> None:
    ep = _ep("/api/users", "https://sandbox.example.com/app.js")
    tagged = tag_endpoints([ep], [], set(), [], [])
    assert tagged[0].environment == "staging"


def test_qa_environment_tagged_as_staging() -> None:
    ep = _ep("/api/users", "https://qa.example.com/app.js")
    tagged = tag_endpoints([ep], [], set(), [], [])
    assert tagged[0].environment == "staging"


def test_uat_environment_tagged_as_staging() -> None:
    ep = _ep("/api/users", "https://uat.example.com/app.js")
    tagged = tag_endpoints([ep], [], set(), [], [])
    assert tagged[0].environment == "staging"


def test_localhost_tagged_as_dev() -> None:
    ep = _ep("/api/users", "http://localhost:3000/app.js")
    tagged = tag_endpoints([ep], [], set(), [], [])
    assert tagged[0].environment == "dev"


def test_environment_field_default_unknown() -> None:
    ep = Endpoint(value="/api/x", pattern_name="url_path", source_url="https://example.com/x.js")
    assert ep.environment == "unknown"


def test_environment_does_not_affect_tag() -> None:
    ep = _ep("/api/users", "https://staging.example.com/app.js")
    tagged = tag_endpoints([ep], ["https://staging.example.com/api/users"], set(), [], [])
    assert tagged[0].tag == "live"
    assert tagged[0].environment == "staging"
