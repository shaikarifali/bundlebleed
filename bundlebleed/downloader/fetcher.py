from __future__ import annotations

import asyncio
import re
from urllib.parse import urljoin

from bundlebleed.downloader.http_client import GuardedHttpClient
from bundlebleed.downloader.sourcemap import parse_source_map
from bundlebleed.models import FetchedFile

_SOURCE_MAP_COMMENT = re.compile(r"//[#@]\s*sourceMappingURL=(\S+)")
_JS_URL_HINT = re.compile(r"\.js(?:[?#]|$)", re.IGNORECASE)
_STATIC_ASSET_HINT = re.compile(
    r"\.(?:css|png|jpe?g|gif|svg|ico|webp|woff2?|ttf|eot|otf|mp4|mp3|pdf|zip|map)(?:[?#]|$)",
    re.IGNORECASE,
)


def looks_like_js(url: str) -> bool:
    return bool(_JS_URL_HINT.search(url))


def looks_like_page(url: str) -> bool:
    """True for URLs worth fetching as an HTML page for link/form/parameter
    extraction — i.e. not already-handled JS, and not a static asset whose
    body has no recon value (images, fonts, stylesheets, ...)."""
    return not looks_like_js(url) and not _STATIC_ASSET_HINT.search(url)


def _resolve_source_map_url(js_url: str, content: str) -> str | None:
    match = _SOURCE_MAP_COMMENT.search(content)
    if not match:
        return None
    ref = str(match.group(1))
    if ref.startswith(("http://", "https://")):
        return ref
    return urljoin(js_url, ref)


async def fetch_js_files(
    urls: list[str], client: GuardedHttpClient, concurrency: int = 5
) -> list[FetchedFile]:
    """Download the body of every JS-looking URL (ScopeGuard-gated inside
    `client`), and follow a `//# sourceMappingURL=` reference if present —
    recovering any original, unminified source files the map embeds in its
    own `sourcesContent` (often far richer than the shipped bundle: real
    variable names, comments, debug-only endpoints) as additional entries.

    Never raises: a failed fetch is simply absent from the result.
    """
    js_urls = [u for u in urls if looks_like_js(u)]
    semaphore = asyncio.Semaphore(concurrency)

    async def fetch_one(url: str) -> list[FetchedFile]:
        async with semaphore:
            result = await client.get_text_with_headers(url)
        if result is None:
            return []
        content, headers = result

        source_map_url = _resolve_source_map_url(url, content)
        source_map_found = False
        recovered: list[FetchedFile] = []
        if source_map_url is not None:
            async with semaphore:
                source_map_content = await client.get_text(source_map_url)
            source_map_found = source_map_content is not None
            if source_map_content is not None:
                recovered = parse_source_map(source_map_content, source_map_url)

        return [
            FetchedFile(
                url=url,
                content=content,
                source_map_url=source_map_url,
                source_map_found=source_map_found,
                headers=headers,
            ),
            *recovered,
        ]

    results = await asyncio.gather(*(fetch_one(u) for u in js_urls))
    return [f for group in results for f in group]


async def fetch_page_files(
    urls: list[str], client: GuardedHttpClient, concurrency: int = 5
) -> list[FetchedFile]:
    """Download the body of every non-JS, non-static-asset URL (ScopeGuard-
    gated inside `client`) for link/form/parameter extraction — the same
    plain GET a browser makes loading the page, just never sent anywhere
    the guard hasn't already allowed.

    Never raises: a failed fetch is simply absent from the result.
    """
    page_urls = [u for u in urls if looks_like_page(u)]
    semaphore = asyncio.Semaphore(concurrency)

    async def fetch_one(url: str) -> FetchedFile | None:
        async with semaphore:
            result = await client.get_text_with_headers(url)
        if result is None:
            return None
        content, headers = result
        return FetchedFile(url=url, content=content, headers=headers)

    results = await asyncio.gather(*(fetch_one(u) for u in page_urls))
    return [r for r in results if r is not None]
