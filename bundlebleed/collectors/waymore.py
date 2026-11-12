from __future__ import annotations

from bundlebleed.collectors.base import run_subprocess_lines


class WaymoreCollector:
    """Wraps `waymore` — queries Wayback Machine, CommonCrawl, AlienVault OTX,
    and URLScan.io simultaneously for historical URLs.

    Passive only: queries archives, never contacts the target directly.
    Degrades silently if `waymore` is not installed.
    Install: pipx install waymore
    """

    name = "waymore"

    async def collect(self, domain: str, seed_urls: list[str]) -> list[str]:
        return await run_subprocess_lines(
            self.name, "waymore", "-i", domain, "-mode", "U", domain=domain
        )
