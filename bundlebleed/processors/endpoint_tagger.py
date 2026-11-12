from __future__ import annotations

import re
from urllib.parse import urlparse

from bundlebleed.models import Endpoint

_HISTORICAL_COLLECTORS = frozenset(["gau", "wayback", "waymore"])
_ACTIVE_COLLECTORS = frozenset(["katana", "getjs"])

_ENV_STAGING = re.compile(
    r"(?:^|\.)(?:staging|stage|stg|uat|sit|preprod|pre-prod|preview|test|qa|sandbox|dev|develop|development|local|localhost)",
    re.IGNORECASE,
)
_ENV_DEV = re.compile(
    r"(?:^|\.)(?:dev|develop|development|local|localhost|127\.0\.0\.1)",
    re.IGNORECASE,
)


def _classify_environment(source_url: str) -> str:
    try:
        host = urlparse(source_url).hostname or ""
    except Exception:
        return "unknown"
    if _ENV_DEV.search(host):
        return "dev"
    if _ENV_STAGING.search(host):
        return "staging"
    if host:
        return "prod"
    return "unknown"


def tag_endpoints(
    endpoints: list[Endpoint],
    collected_urls: list[str],
    historical_urls: set[str],
    auth_only_js_urls: list[str],
    runtime_confirmed_paths: list[str],
) -> list[Endpoint]:
    """Apply provenance tags to discovered endpoints.

    Tags (in priority order):
    - auth-required: endpoint URL appeared only in an authenticated JS file
    - historical: endpoint value not found in any live-crawl URL
    - live: default — found in a live-crawl URL or runtime-confirmed path
    - unauthed: endpoint path was runtime-confirmed without an auth session

    Tags are informational signals for triage, not authoritative access verdicts.
    """
    live_paths = {urlparse(u).path for u in collected_urls}
    runtime_paths = set(runtime_confirmed_paths)
    auth_url_set = set(auth_only_js_urls)

    tagged: list[Endpoint] = []
    for ep in endpoints:
        ep_path = ep.value if ep.value.startswith("/") else f"/{ep.value.lstrip('/')}"

        if ep.source_url in auth_url_set:
            tag = "auth-required"
        elif ep_path in runtime_paths:
            tag = "live"
        elif ep.value in historical_urls or ep_path not in live_paths:
            tag = "historical"
        else:
            tag = "live"

        env = _classify_environment(ep.source_url)
        tagged.append(ep.model_copy(update={"tag": tag, "environment": env}))

    return tagged
