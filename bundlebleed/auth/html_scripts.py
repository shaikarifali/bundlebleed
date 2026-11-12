from __future__ import annotations

import re
from urllib.parse import urljoin

_SCRIPT_SRC_RE = re.compile(r"""<script[^>]+src=["']([^"']+)["']""", re.IGNORECASE)


def extract_script_urls(html: str, page_url: str) -> list[str]:
    """Extract `<script src="...">` references, resolved against the page's
    own URL. Order-preserving, deduplicated."""
    seen: set[str] = set()
    urls: list[str] = []
    for match in _SCRIPT_SRC_RE.finditer(html):
        resolved = urljoin(page_url, match.group(1))
        if resolved not in seen:
            seen.add(resolved)
            urls.append(resolved)
    return urls
