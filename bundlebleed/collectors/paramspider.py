from __future__ import annotations

import tempfile
from pathlib import Path

from bundlebleed.collectors.base import run_subprocess_capturing_file


class ParamSpiderCollector:
    """Wraps `paramspider` (github.com/devanshbatham/ParamSpider) — mines
    Wayback Machine archives specifically for URLs carrying query
    parameters, a narrower but higher-signal slice of the same archive data
    gau/waybackurls already cover: a URL with `?token=`, `?redirect=`,
    `?id=`, etc. is immediately more interesting than a bare path.

    As of this writing paramspider writes its results to a file rather than
    stdout (`-o <path>`), unlike gau/waybackurls — this collector gives it a
    throwaway temp path and reads that back, same as WaymoreCollector.
    """

    name = "paramspider"

    async def collect(self, domain: str, seed_urls: list[str]) -> list[str]:
        # paramspider queries archives by domain; it has no notion of a starting URL.
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "paramspider-urls.txt"
            return await run_subprocess_capturing_file(
                self.name,
                "paramspider",
                "-d",
                domain,
                "-o",
                str(output_path),
                domain=domain,
                output_path=output_path,
            )
