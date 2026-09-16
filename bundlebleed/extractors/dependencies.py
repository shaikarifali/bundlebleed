from __future__ import annotations

import re

from bundlebleed.extractors.patterns import load_vulnerable_library_patterns
from bundlebleed.models import VulnerableLibraryFinding

_VERSION_PART_RE = re.compile(r"\d+")


def _version_tuple(version: str) -> tuple[int, ...]:
    parts = _VERSION_PART_RE.findall(version)
    return tuple(int(p) for p in parts) if parts else (0,)


def extract_vulnerable_libraries(content: str, source_url: str) -> list[VulnerableLibraryFinding]:
    """Match a library's own version banner against a small, curated list
    of known-CVE version thresholds (Retire.js-style fingerprinting, not a
    full mirror of its database).

    Terser/UglifyJS preserve `/*! ... */` comments by default, which is why
    a version banner usually survives minification -- a build that strips
    it produces a false negative here, never a false positive.
    """
    findings: list[VulnerableLibraryFinding] = []
    for pattern in load_vulnerable_library_patterns():
        match = pattern.regex.search(content)
        if not match or not match.groups():
            continue
        detected_version = match.group(1)
        if _version_tuple(detected_version) >= _version_tuple(pattern.vulnerable_below):
            continue
        findings.append(
            VulnerableLibraryFinding(
                source_url=source_url,
                library_name=pattern.name,
                detected_version=detected_version,
                vulnerable_below=pattern.vulnerable_below,
                cve=pattern.cve,
                severity=pattern.severity,
                description=pattern.description,
            )
        )
    return findings
