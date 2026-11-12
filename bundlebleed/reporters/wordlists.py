from __future__ import annotations

from pathlib import Path

from bundlebleed.models import ScanResult


def _write_lines(path: Path, lines: list[str]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(f"{line}\n" for line in lines))
    return path


def write_wordlists(result: ScanResult, output_dir: Path) -> dict[str, Path]:
    """Write plain, line-delimited wordlists for piping straight into other
    tools (ffuf, httpx, Burp Intruder, nuclei, ...) — the same format
    gau/waybackurls/katana already use. Only ever a different serialization
    of data BundleBleed already collected/extracted; no new network
    activity, no new data exposure.

    Subdomains are limited to ones ScopeGuard already classified in-scope —
    a flagged-for-manual-review subdomain is deliberately left out of a
    file meant to be piped straight into other tooling that has no
    ScopeGuard of its own; it's still visible in the JSON/Markdown/HTML
    reports.
    """
    r = result.normalized()
    wordlists_dir = output_dir / "wordlists"

    return {
        "urls": _write_lines(wordlists_dir / "urls.txt", r.collected_urls),
        "endpoints": _write_lines(
            wordlists_dir / "endpoints.txt", sorted({e.value for e in r.endpoints})
        ),
        "parameters": _write_lines(
            wordlists_dir / "parameters.txt", sorted({p.name for p in r.parameters})
        ),
        "subdomains": _write_lines(
            wordlists_dir / "subdomains.txt",
            sorted({s.domain for s in r.subdomains if s.in_scope}),
        ),
        "third_party_hosts": _write_lines(
            wordlists_dir / "third-party-hosts.txt",
            sorted({t.hostname for t in r.third_party_scripts}),
        ),
    }
