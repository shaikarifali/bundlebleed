from __future__ import annotations

from bundlebleed.auth.html_scripts import extract_script_urls
from bundlebleed.auth.models import AuthSession
from bundlebleed.downloader.http_client import GuardedHttpClient


async def fetch_authenticated_script_urls(
    page_urls: list[str], session: AuthSession, client: GuardedHttpClient
) -> list[str]:
    """Fetch each page WITH the session's cookie attached and extract
    `<script src>` references. Every fetch still goes through ScopeGuard
    inside `client` — this only adds a Cookie header, it never bypasses
    scope enforcement, and it never sends anything but a GET.

    The cookie value is never returned, logged, or stored by this function
    — only the resulting script URLs.
    """
    discovered: set[str] = set()
    for url in page_urls:
        html = await client.get_text(url, extra_headers={"Cookie": session.cookie_header})
        if html is None:
            continue
        discovered.update(extract_script_urls(html, url))
    return sorted(discovered)
