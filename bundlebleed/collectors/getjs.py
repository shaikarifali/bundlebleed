from __future__ import annotations

from bundlebleed.collectors.base import run_subprocess_lines


class GetJSCollector:
    """Wraps `getJS` — dedicated JS URL collector that follows script tags,
    deduplicates, and resolves relative references.

    Passive collector: queries the target's HTML for script URLs only —
    no crawling beyond initial page fetch.
    Degrades silently if `getJS` is not installed.
    Install: go install github.com/003random/getJS@latest
    """

    name = "getjs"

    async def collect(self, domain: str, seed_urls: list[str]) -> list[str]:
        target = seed_urls[0] if seed_urls else f"https://{domain}"
        return await run_subprocess_lines(
            self.name, "getJS", "--url", target, "--complete", domain=domain
        )
