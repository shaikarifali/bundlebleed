from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable


class RateLimiter:
    """Fixed-interval async rate limiter shared across all callers: at most
    `requests_per_second` calls to `acquire()` complete per second.
    `requests_per_second=None` (or <= 0) makes `acquire()` a no-op.

    `clock`/`sleep` are injectable so tests can verify pacing without
    actually waiting in real time.
    """

    def __init__(
        self,
        requests_per_second: float | None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self._interval = (
            1.0 / requests_per_second if requests_per_second and requests_per_second > 0 else 0.0
        )
        self._lock = asyncio.Lock()
        self._next_allowed = 0.0
        self._clock = clock
        self._sleep = sleep

    async def acquire(self) -> None:
        if self._interval <= 0:
            return
        async with self._lock:
            now = self._clock()
            wait = self._next_allowed - now
            if wait > 0:
                await self._sleep(wait)
                now = self._clock()
            self._next_allowed = max(now, self._next_allowed) + self._interval
