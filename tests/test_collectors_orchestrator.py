from __future__ import annotations

import asyncio

import pytest

import bundlebleed.collectors.orchestrator as orch
from bundlebleed.config import BundleBleedConfig
from bundlebleed.scope.guard import ScopeGuard
from bundlebleed.scope.models import MatchType, ScanSettings, ScopeConfig, ScopeEntry


class FakeCollector:
    def __init__(self, name: str, urls: list[str]) -> None:
        self.name = name
        self._urls = urls
        self.calls: list[str] = []
        self.seed_url_calls: list[list[str]] = []

    async def collect(self, domain: str, seed_urls: list[str]) -> list[str]:
        self.calls.append(domain)
        self.seed_url_calls.append(seed_urls)
        return self._urls


class RaisingCollector:
    name = "raising"

    async def collect(self, domain: str, seed_urls: list[str]) -> list[str]:
        raise AssertionError(f"should never be called for {domain}")


def _in_scope_config() -> ScopeConfig:
    return ScopeConfig(
        in_scope=[ScopeEntry(domain="example.com", match_type=MatchType.WILDCARD)],
        out_of_scope=["blog.example.com"],
    )


def test_collect_all_filters_urls_through_scope_guard(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeCollector(
        "fake",
        [
            "https://api.example.com/a.js",
            "https://api.example.com/a.js",  # duplicate, should collapse
            "https://blog.example.com/b.js",  # out-of-scope override
            "https://not-related.com/c.js",  # not in scope at all
        ],
    )
    monkeypatch.setattr(orch, "PASSIVE_COLLECTORS", [fake])
    monkeypatch.setattr(orch, "ACTIVE_COLLECTORS", [RaisingCollector()])

    scope_config = _in_scope_config()
    guard = ScopeGuard(scope_config)
    config = BundleBleedConfig(active_scan_enabled=False)

    allowed, denied = asyncio.run(
        orch.collect_all(["example.com"], scope_config, guard, config, cli_active_flag=False)
    )

    assert allowed == ["https://api.example.com/a.js"]
    assert denied == sorted(["https://blog.example.com/b.js", "https://not-related.com/c.js"])
    assert fake.calls == ["example.com"]


def test_collect_all_merges_seed_urls_through_scope_guard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeCollector("fake", ["https://api.example.com/a.js"])
    monkeypatch.setattr(orch, "PASSIVE_COLLECTORS", [fake])
    monkeypatch.setattr(orch, "ACTIVE_COLLECTORS", [RaisingCollector()])

    scope_config = _in_scope_config()
    guard = ScopeGuard(scope_config)
    config = BundleBleedConfig(active_scan_enabled=False)

    allowed, denied = asyncio.run(
        orch.collect_all(
            ["example.com"],
            scope_config,
            guard,
            config,
            cli_active_flag=False,
            seed_urls=[
                "https://api.example.com/seed.js",  # in scope, should be allowed
                "https://evil.com/x.js",  # out of scope, must still be denied
            ],
        )
    )

    assert allowed == ["https://api.example.com/a.js", "https://api.example.com/seed.js"]
    assert "https://evil.com/x.js" in denied


def test_collect_all_works_with_no_targets_when_only_seed_urls_given(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A freshly provisioned/JS-heavy SPA target with nothing in gau/wayback's
    # archives -- seed_urls alone must still work with an empty target list.
    monkeypatch.setattr(orch, "PASSIVE_COLLECTORS", [])
    scope_config = _in_scope_config()
    guard = ScopeGuard(scope_config)
    config = BundleBleedConfig(active_scan_enabled=False)

    allowed, denied = asyncio.run(
        orch.collect_all(
            [],
            scope_config,
            guard,
            config,
            cli_active_flag=False,
            seed_urls=["https://api.example.com/seed.js"],
        )
    )

    assert allowed == ["https://api.example.com/seed.js"]
    assert denied == []


def test_active_collector_receives_domain_matched_scope_allowed_seed_urls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    active = FakeCollector("active", [])
    monkeypatch.setattr(orch, "PASSIVE_COLLECTORS", [])
    monkeypatch.setattr(orch, "ACTIVE_COLLECTORS", [active])

    scope_config = ScopeConfig(
        in_scope=[
            ScopeEntry(domain="example.com", match_type=MatchType.EXACT),
            ScopeEntry(domain="other.com", match_type=MatchType.EXACT),
        ],
        excluded_paths=["/admin"],
        authorization_attested=True,
    )
    guard = ScopeGuard(scope_config)
    config = BundleBleedConfig(active_scan_enabled=True)

    asyncio.run(
        orch.collect_all(
            ["example.com", "other.com"],
            scope_config,
            guard,
            config,
            cli_active_flag=True,
            seed_urls=[
                "https://example.com/app",  # matches this domain, in scope -> passed through
                "https://example.com/admin",  # matches domain but excluded path -> filtered out
                "https://other.com/x",  # a different target domain -> not passed to example.com
            ],
        )
    )

    assert active.seed_url_calls[0] == ["https://example.com/app"]
    assert active.seed_url_calls[1] == ["https://other.com/x"]


def test_collect_all_skips_out_of_scope_domain_without_invoking_collectors() -> None:
    scope_config = ScopeConfig(
        in_scope=[ScopeEntry(domain="example.com", match_type=MatchType.EXACT)]
    )
    guard = ScopeGuard(scope_config)

    async def run() -> list[str]:
        return await orch._collect_domain("other.com", guard, [RaisingCollector()], [])

    result = asyncio.run(run())
    assert result == []


@pytest.mark.parametrize(
    "config_flag,cli_flag,attested,expected",
    [
        (True, True, True, True),
        (False, True, True, False),
        (True, False, True, False),
        (True, True, False, False),
        (False, False, False, False),
    ],
)
def test_active_scan_authorized_requires_all_three(
    config_flag: bool, cli_flag: bool, attested: bool, expected: bool
) -> None:
    config = BundleBleedConfig(active_scan_enabled=config_flag)
    scope_config = ScopeConfig(authorization_attested=attested)
    assert orch.active_scan_authorized(config, scope_config, cli_flag) is expected


def test_active_collectors_run_only_when_fully_authorized(monkeypatch: pytest.MonkeyPatch) -> None:
    passive = FakeCollector("passive", ["https://api.example.com/passive.js"])
    active = FakeCollector("active", ["https://api.example.com/active.js"])
    monkeypatch.setattr(orch, "PASSIVE_COLLECTORS", [passive])
    monkeypatch.setattr(orch, "ACTIVE_COLLECTORS", [active])

    scope_config = ScopeConfig(
        in_scope=[ScopeEntry(domain="example.com", match_type=MatchType.WILDCARD)],
        authorization_attested=True,
    )
    guard = ScopeGuard(scope_config)
    config = BundleBleedConfig(active_scan_enabled=True)

    allowed, _ = asyncio.run(
        orch.collect_all(["example.com"], scope_config, guard, config, cli_active_flag=True)
    )
    assert "https://api.example.com/active.js" in allowed

    # flip just the CLI flag off -- active collector must not run
    passive.calls.clear()
    active.calls.clear()
    allowed, _ = asyncio.run(
        orch.collect_all(["example.com"], scope_config, guard, config, cli_active_flag=False)
    )
    assert "https://api.example.com/active.js" not in allowed
    assert active.calls == []


def test_collect_all_sleeps_between_domains_but_not_before_the_first(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeCollector("fake", [])
    monkeypatch.setattr(orch, "PASSIVE_COLLECTORS", [fake])
    monkeypatch.setattr(orch, "ACTIVE_COLLECTORS", [])

    scope_config = ScopeConfig(
        in_scope=[
            ScopeEntry(domain="a.com", match_type=MatchType.EXACT),
            ScopeEntry(domain="b.com", match_type=MatchType.EXACT),
            ScopeEntry(domain="c.com", match_type=MatchType.EXACT),
        ],
        scan=ScanSettings(delay_between_domains=3.0),
    )
    guard = ScopeGuard(scope_config)
    config = BundleBleedConfig()

    sleeps: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)

    asyncio.run(
        orch.collect_all(
            ["a.com", "b.com", "c.com"],
            scope_config,
            guard,
            config,
            cli_active_flag=False,
            sleep_fn=fake_sleep,
        )
    )

    assert sleeps == [3.0, 3.0]
    assert fake.calls == ["a.com", "b.com", "c.com"]


def test_collect_all_never_sleeps_when_delay_is_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeCollector("fake", [])
    monkeypatch.setattr(orch, "PASSIVE_COLLECTORS", [fake])
    monkeypatch.setattr(orch, "ACTIVE_COLLECTORS", [])

    scope_config = ScopeConfig(
        in_scope=[
            ScopeEntry(domain="a.com", match_type=MatchType.EXACT),
            ScopeEntry(domain="b.com", match_type=MatchType.EXACT),
        ]
    )
    guard = ScopeGuard(scope_config)
    config = BundleBleedConfig()

    async def failing_sleep(seconds: float) -> None:
        raise AssertionError("should never sleep when delay_between_domains is 0")

    asyncio.run(
        orch.collect_all(
            ["a.com", "b.com"],
            scope_config,
            guard,
            config,
            cli_active_flag=False,
            sleep_fn=failing_sleep,
        )
    )
