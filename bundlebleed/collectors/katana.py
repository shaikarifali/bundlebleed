from __future__ import annotations

from bundlebleed.collectors.base import run_subprocess_lines


class KatanaCollector:
    """Wraps `katana` — a JS-aware headless crawler that sends real requests to
    the target. This is ACTIVE, not passive: the orchestrator must only invoke
    it when active scanning has been explicitly enabled (config flag + CLI flag
    + authorization attestation in scope.yaml — see CLAUDE.md Invariant 3)."""

    name = "katana"

    async def collect(self, domain: str, seed_urls: list[str]) -> list[str]:
        """Crawl from the bare domain, plus any given seed URLs as
        additional starting points — e.g. a specific known-good path on a
        freshly provisioned target, rather than whatever katana's own
        discovery from the bare domain happens to find. The orchestrator
        has already domain-matched and individually ScopeGuard-ALLOWed
        every seed URL before it reaches here.
        """
        args = ["katana", "-u", domain]
        for url in seed_urls:
            args += ["-u", url]
        args += ["-silent", "-jc"]
        return await run_subprocess_lines(self.name, *args, domain=domain)
