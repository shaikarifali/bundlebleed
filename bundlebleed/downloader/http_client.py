from __future__ import annotations

import httpx
import structlog

from bundlebleed.ratelimit import RateLimiter
from bundlebleed.scope.guard import ScopeGuard

logger = structlog.get_logger(__name__)


class GuardedHttpClient:
    """The only component allowed to send a GET to a target.

    Every request is preceded by a ScopeGuard check (which itself logs an
    audit row for the ALLOW/DENY) — a DENY never reaches the network, and
    never consumes rate-limit budget either.
    """

    def __init__(
        self,
        guard: ScopeGuard,
        client: httpx.AsyncClient | None = None,
        rate_limiter: RateLimiter | None = None,
    ) -> None:
        self._guard = guard
        self._client = client or httpx.AsyncClient(timeout=10.0, follow_redirects=True)
        self._owns_client = client is None
        self._rate_limiter = rate_limiter or RateLimiter(requests_per_second=None)

    async def _get(
        self, url: str, extra_headers: dict[str, str] | None = None
    ) -> httpx.Response | None:
        if not self._guard.allowed(url):
            return None
        await self._rate_limiter.acquire()
        try:
            response = await self._client.get(url, headers=extra_headers)
        except httpx.HTTPError as exc:
            logger.warning("downloader.request_failed", url=url, error=str(exc))
            return None
        if response.status_code != 200:
            logger.info("downloader.non_200", url=url, status=response.status_code)
            return None
        return response

    async def get_text(self, url: str, extra_headers: dict[str, str] | None = None) -> str | None:
        """`extra_headers` values (e.g. a session Cookie) are sent to the
        target but are NEVER logged here — only the url is."""
        response = await self._get(url, extra_headers)
        return response.text if response is not None else None

    async def get_text_with_headers(
        self, url: str, extra_headers: dict[str, str] | None = None
    ) -> tuple[str, dict[str, str]] | None:
        """Same single guarded GET as `get_text`, but also returns the
        response headers (lowercased keys) — for callers that need to
        inspect them (e.g. CORS misconfiguration detection) without a
        second request to the same URL."""
        response = await self._get(url, extra_headers)
        if response is None:
            return None
        return response.text, {k.lower(): v for k, v in response.headers.items()}

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()
