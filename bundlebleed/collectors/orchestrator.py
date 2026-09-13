from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from urllib.parse import urlsplit

import structlog

from bundlebleed.collectors.base import Collector
from bundlebleed.collectors.gau import GauCollector
from bundlebleed.collectors.katana import KatanaCollector
from bundlebleed.collectors.wayback import WaybackCollector
from bundlebleed.config import BundleBleedConfig
from bundlebleed.scope.guard import ScopeGuard
from bundlebleed.scope.models import Decision, ScopeConfig

logger = structlog.get_logger(__name__)

PASSIVE_COLLECTORS: list[Collector] = [GauCollector(), WaybackCollector()]
ACTIVE_COLLECTORS: list[Collector] = [KatanaCollector()]


def active_scan_authorized(
    config: BundleBleedConfig, scope_config: ScopeConfig, cli_active_flag: bool
) -> bool:
    """Invariant 3: active scanning requires an explicit config flag AND a CLI
    flag AND a valid authorization attestation in scope.yaml. All three or none."""
    return bool(
        config.active_scan_enabled and cli_active_flag and scope_config.authorization_attested
    )


def _seed_urls_for_domain(domain: str, seed_urls: list[str], guard: ScopeGuard) -> list[str]:
    """Seed URLs handed to an ACTIVE collector (which sends them real
    requests) must be individually ScopeGuard-ALLOWed, not just domain-name
    matched — a domain can be in scope while a specific path on it is
    excluded (Invariant 2: no code path acts on a URL without an ALLOW)."""
    return [u for u in seed_urls if urlsplit(u).netloc == domain and guard.allowed(u)]


async def _collect_domain(
    domain: str, guard: ScopeGuard, collectors: list[Collector], seed_urls: list[str]
) -> list[str]:
    """Scope-check the domain itself before any collector — which shells out to a
    tool that will contact it — ever runs."""
    if not guard.allowed(domain):
        logger.info("orchestrator.domain_skipped", domain=domain)
        return []

    domain_seed_urls = _seed_urls_for_domain(domain, seed_urls, guard)
    results = await asyncio.gather(*(c.collect(domain, domain_seed_urls) for c in collectors))
    merged: list[str] = []
    for urls in results:
        merged.extend(urls)
    return merged


async def collect_all(
    targets: list[str],
    scope_config: ScopeConfig,
    guard: ScopeGuard,
    config: BundleBleedConfig,
    cli_active_flag: bool = False,
    seed_urls: list[str] | None = None,
    sleep_fn: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> tuple[list[str], list[str]]:
    """Run collectors for every target domain, then re-validate every returned
    URL through ScopeGuard before it is accepted into the result set.

    `seed_urls` (e.g. from --seed-url) are merged in before filtering — they
    get exactly the same ScopeGuard check as anything a collector returns;
    one outside the declared scope is denied and logged, never a bypass.
    Essential for a freshly provisioned or JS-heavy SPA target gau/wayback
    have no archive history for. When active scanning is authorized, each
    domain's own (domain-matched, individually ScopeGuard-ALLOWed) seed
    URLs are also handed to katana as additional crawl starting points —
    a specific known-good path often finds far more than crawling from the
    bare domain alone.

    Pauses `scope_config.scan.delay_between_domains` seconds between domains
    (not before the first) — `sleep_fn` is injectable so tests can verify
    pacing without a real wait.

    Returns (allowed_urls, denied_urls), both deduplicated and sorted for
    deterministic, idempotent output.
    """
    collectors = list(PASSIVE_COLLECTORS)
    if active_scan_authorized(config, scope_config, cli_active_flag):
        collectors += ACTIVE_COLLECTORS
    else:
        logger.info("orchestrator.active_scan_skipped", reason="not authorized")

    delay = scope_config.scan.delay_between_domains
    seed_urls = seed_urls or []
    raw_urls: list[str] = list(seed_urls)
    for i, domain in enumerate(targets):
        if i > 0 and delay > 0:
            await sleep_fn(delay)
        raw_urls.extend(await _collect_domain(domain, guard, collectors, seed_urls))

    allowed: set[str] = set()
    denied: set[str] = set()
    for url in raw_urls:
        decision = guard.check(url)
        if decision.decision == Decision.ALLOW:
            allowed.add(url)
        else:
            denied.add(url)
            logger.info("orchestrator.url_dropped", url=url, reason=decision.reason)

    return sorted(allowed), sorted(denied)
