from __future__ import annotations

import tempfile
from pathlib import Path

from bundlebleed.collectors.base import run_subprocess_capturing_file


class WaymoreCollector:
    """Wraps `waymore` (github.com/xnl-h4ck3r/waymore) — aggregates URLs from
    a wider archive set than gau/waybackurls alone: Wayback Machine, Common
    Crawl, AlienVault OTX, URLScan.io, Intelligence X, and VirusTotal (the
    last two only when their API keys are configured in waymore's own config
    file — this collector never supplies or requires one).

    `-mode U` runs waymore's fast URL-only pass, skipping the slower
    response-fetching/filtering mode entirely, since only the URL list is
    needed here. As of this writing waymore writes its results to a file
    rather than stdout (`-oU <path>`), unlike gau/waybackurls — this
    collector gives it a throwaway temp path and reads that back.
    """

    name = "waymore"

    async def collect(self, domain: str, seed_urls: list[str]) -> list[str]:
        # waymore queries archives by domain; it has no notion of a starting URL.
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "waymore-urls.txt"
            return await run_subprocess_capturing_file(
                self.name,
                "waymore",
                "-i",
                domain,
                "-mode",
                "U",
                "-oU",
                str(output_path),
                domain=domain,
                output_path=output_path,
            )
