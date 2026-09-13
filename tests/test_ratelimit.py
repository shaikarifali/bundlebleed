from __future__ import annotations

import asyncio

from bundlebleed.ratelimit import RateLimiter


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def test_no_limit_never_sleeps() -> None:
    clock = FakeClock()
    sleeps: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)

    limiter = RateLimiter(None, clock=clock, sleep=fake_sleep)

    async def run() -> None:
        for _ in range(5):
            await limiter.acquire()

    asyncio.run(run())
    assert sleeps == []


def test_rate_limit_paces_calls_at_the_configured_interval() -> None:
    clock = FakeClock()
    sleeps: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)
        clock.now += seconds  # simulate time passing while "asleep"

    limiter = RateLimiter(2.0, clock=clock, sleep=fake_sleep)  # 0.5s between calls

    async def run() -> None:
        await limiter.acquire()  # t=0, no wait needed
        await limiter.acquire()  # must wait until t=0.5
        await limiter.acquire()  # must wait until t=1.0

    asyncio.run(run())
    assert sleeps == [0.5, 0.5]


def test_rate_limit_does_not_sleep_if_caller_was_already_slow() -> None:
    clock = FakeClock()
    sleeps: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)

    limiter = RateLimiter(2.0, clock=clock, sleep=fake_sleep)  # 0.5s interval

    async def run() -> None:
        await limiter.acquire()
        clock.now += 10  # plenty of real time passed between calls
        await limiter.acquire()

    asyncio.run(run())
    assert sleeps == []
