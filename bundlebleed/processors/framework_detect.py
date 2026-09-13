from __future__ import annotations

from bundlebleed.extractors.patterns import load_framework_patterns


def detect_frameworks(content: str) -> list[str]:
    return sorted({p.name for p in load_framework_patterns() if p.regex.search(content)})
