from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Protocol

import structlog

logger = structlog.get_logger(__name__)


class Collector(Protocol):
    """A URL source. `collect()` returns raw, unfiltered URLs — the
    orchestrator is responsible for running every result through ScopeGuard
    before it is used or persisted.

    `seed_urls` are already domain-matched and individually ScopeGuard-ALLOWed
    by the orchestrator before a collector ever sees them (Invariant 2 — no
    code path may act on a URL without an ALLOW, and an active collector
    sends real requests to whatever it's given). Passive collectors (gau,
    waybackurls, waymore, ParamSpider) query archives by domain and have no
    use for a starting URL; only an active, crawl-based collector (katana)
    uses them as additional crawl seeds.
    """

    name: str

    async def collect(self, domain: str, seed_urls: list[str]) -> list[str]: ...


async def run_subprocess_lines(name: str, *args: str, domain: str) -> list[str]:
    """Run an external CLI tool and return its stdout as a list of non-empty lines.

    Never raises on tool failure — a missing binary or non-zero exit is logged
    and treated as zero results, so one broken collector never aborts a scan.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        logger.warning("collector.binary_not_found", collector=name, domain=domain, binary=args[0])
        return []

    stdout, stderr = await proc.communicate()
    if proc.returncode != 0:
        logger.warning(
            "collector.failed",
            collector=name,
            domain=domain,
            returncode=proc.returncode,
            stderr=stderr.decode(errors="replace")[:500],
        )
        return []

    return [line.strip() for line in stdout.decode(errors="replace").splitlines() if line.strip()]


async def run_subprocess_capturing_file(
    name: str, *args: str, domain: str, output_path: Path
) -> list[str]:
    """Like `run_subprocess_lines`, but for a tool (waymore, ParamSpider) that
    writes its results to a file rather than stdout. `output_path` must
    already be present in `args` wherever that tool expects its output-file
    flag's value — this function only reads it back afterward.

    Same failure handling as `run_subprocess_lines`: a missing binary, a
    non-zero exit, or the tool simply never writing the file are all treated
    as zero results, never an error that could abort the scan.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        logger.warning("collector.binary_not_found", collector=name, domain=domain, binary=args[0])
        return []

    _, stderr = await proc.communicate()
    if proc.returncode != 0:
        logger.warning(
            "collector.failed",
            collector=name,
            domain=domain,
            returncode=proc.returncode,
            stderr=stderr.decode(errors="replace")[:500],
        )
        return []

    if not output_path.exists():
        return []
    return [
        line.strip()
        for line in output_path.read_text(errors="replace").splitlines()
        if line.strip()
    ]
