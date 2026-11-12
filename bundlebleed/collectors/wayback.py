from __future__ import annotations

from bundlebleed.collectors.base import run_subprocess_lines


class WaybackCollector:
    """Wraps `waybackurls` — fetches all URLs the Wayback Machine has archived
    for a domain, including old JS files that may still contain live endpoints."""

    name = "wayback"

    async def collect(self, domain: str, seed_urls: list[str]) -> list[str]:
        # waybackurls queries the Wayback Machine's archive by domain; it has
        # no notion of a starting URL.
        return await run_subprocess_lines(self.name, "waybackurls", domain, domain=domain)
