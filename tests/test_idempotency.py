from __future__ import annotations

import asyncio
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime

import bundlebleed.collectors.orchestrator as orch
from bundlebleed.config import BundleBleedConfig
from bundlebleed.extractors.endpoints import extract_endpoints
from bundlebleed.extractors.secrets import extract_secrets
from bundlebleed.models import ScanResult
from bundlebleed.scope.guard import ScopeGuard
from bundlebleed.scope.models import MatchType, ScopeConfig, ScopeEntry
from tests.conftest import FIXTURES_DIR
from tests.test_collectors_orchestrator import FakeCollector

REACT_BUNDLE = (FIXTURES_DIR / "js" / "react_bundle.js").read_text()


@contextmanager
def _only_fake_collectors() -> Iterator[None]:
    """Replace the real (subprocess-shelling) collectors so no live tool is
    ever invoked from the test suite, then restore them afterwards."""
    original_passive, original_active = orch.PASSIVE_COLLECTORS, orch.ACTIVE_COLLECTORS
    orch.PASSIVE_COLLECTORS = [
        FakeCollector("fake", ["https://api.example.com/app.js", "https://api.example.com/app.js"])
    ]
    orch.ACTIVE_COLLECTORS = []
    try:
        yield
    finally:
        orch.PASSIVE_COLLECTORS, orch.ACTIVE_COLLECTORS = original_passive, original_active


def _run_pipeline_once() -> ScanResult:
    scope_config = ScopeConfig(
        in_scope=[ScopeEntry(domain="example.com", match_type=MatchType.WILDCARD)]
    )
    guard = ScopeGuard(scope_config)
    config = BundleBleedConfig()

    with _only_fake_collectors():
        allowed, denied = asyncio.run(
            orch.collect_all(["example.com"], scope_config, guard, config, cli_active_flag=False)
        )

    endpoints = extract_endpoints(REACT_BUNDLE, source_url="https://api.example.com/app.js")
    secrets = extract_secrets(REACT_BUNDLE, source_url="https://api.example.com/app.js")

    return ScanResult(
        scan_run_id="irrelevant-varies-per-run",
        started_at=datetime.now(),
        targets=["example.com"],
        collected_urls=allowed,
        denied_urls=denied,
        endpoints=endpoints,
        secrets=secrets,
    )


def test_running_the_same_scan_twice_produces_identical_findings() -> None:
    result_a = _run_pipeline_once()
    result_b = _run_pipeline_once()

    norm_a = result_a.normalized()
    norm_b = result_b.normalized()

    assert norm_a.targets == norm_b.targets
    assert norm_a.collected_urls == norm_b.collected_urls
    assert norm_a.denied_urls == norm_b.denied_urls
    assert norm_a.endpoints == norm_b.endpoints
    assert norm_a.secrets == norm_b.secrets


def test_normalized_dedupes_and_sorts_regardless_of_input_order() -> None:
    endpoints = extract_endpoints(REACT_BUNDLE, source_url="https://example.com/app.js")

    forward = ScanResult(
        scan_run_id="run-1",
        started_at=datetime.now(),
        targets=["b.com", "a.com"],
        collected_urls=["https://b.com/x", "https://a.com/y"],
        endpoints=endpoints,
    )
    shuffled = ScanResult(
        scan_run_id="run-2",
        started_at=datetime.now(),
        targets=["a.com", "b.com", "a.com"],
        collected_urls=["https://a.com/y", "https://b.com/x", "https://a.com/y"],
        endpoints=list(reversed(endpoints)) + endpoints[:1],
    )

    assert forward.normalized().targets == shuffled.normalized().targets
    assert forward.normalized().collected_urls == shuffled.normalized().collected_urls
    assert forward.normalized().endpoints == shuffled.normalized().endpoints
