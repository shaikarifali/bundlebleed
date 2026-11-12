from __future__ import annotations

from bundlebleed.collectors.base import run_subprocess_lines


class GauCollector:
    """Wraps `gau` (GetAllURLs) — aggregates URLs from Wayback, Common Crawl,
    AlienVault OTX, and URLScan.io for a domain."""

    name = "gau"

    async def collect(self, domain: str, seed_urls: list[str]) -> list[str]:
        # gau queries archives by domain; it has no notion of a starting URL.
        return await run_subprocess_lines(self.name, "gau", domain, domain=domain)
