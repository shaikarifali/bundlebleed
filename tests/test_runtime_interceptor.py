from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from bundlebleed.runtime.interceptor import make_route_handler
from bundlebleed.runtime.models import RuntimeEvent
from bundlebleed.scope.guard import ScopeGuard
from bundlebleed.scope.models import MatchType, ScopeConfig, ScopeEntry


@dataclass
class FakeRequest:
    url: str
    method: str = "GET"
    resource_type: str = "document"


@dataclass
class FakeRoute:
    request: FakeRequest
    aborted: bool = False
    continued: bool = False
    fulfilled: bool = False
    calls: list[str] = field(default_factory=list)

    async def abort(self) -> None:
        self.aborted = True
        self.calls.append("abort")

    async def continue_(self) -> None:
        self.continued = True
        self.calls.append("continue")

    async def fulfill(self, **kwargs: object) -> None:
        self.fulfilled = True
        self.calls.append("fulfill")


def _scope() -> ScopeConfig:
    return ScopeConfig(in_scope=[ScopeEntry(domain="example.com", match_type=MatchType.WILDCARD)])


def test_in_scope_request_is_continued() -> None:
    guard = ScopeGuard(_scope())
    events: list[RuntimeEvent] = []
    handler = make_route_handler(guard, events)
    route = FakeRoute(request=FakeRequest(url="https://example.com/app.js"))

    asyncio.run(handler(route))  # type: ignore[arg-type]

    assert route.continued is True
    assert route.aborted is False
    assert events[0].allowed is True


def test_out_of_scope_request_is_aborted() -> None:
    guard = ScopeGuard(_scope())
    events: list[RuntimeEvent] = []
    handler = make_route_handler(guard, events)
    route = FakeRoute(request=FakeRequest(url="https://evil.com/x"))

    asyncio.run(handler(route))  # type: ignore[arg-type]

    assert route.aborted is True
    assert route.continued is False
    assert events[0].allowed is False


def test_out_of_scope_top_level_navigation_is_also_aborted() -> None:
    """A same-page redirect the page's own JS triggers is still just a
    'document' resource_type request — the interceptor treats it exactly
    like any other request, no special-casing needed."""
    guard = ScopeGuard(_scope())
    events: list[RuntimeEvent] = []
    handler = make_route_handler(guard, events)
    route = FakeRoute(request=FakeRequest(url="https://evil.com/phish", resource_type="document"))

    asyncio.run(handler(route))  # type: ignore[arg-type]

    assert route.aborted is True


def test_every_request_is_recorded_as_an_event_regardless_of_outcome() -> None:
    guard = ScopeGuard(_scope())
    events: list[RuntimeEvent] = []
    handler = make_route_handler(guard, events)

    asyncio.run(handler(FakeRoute(request=FakeRequest(url="https://example.com/a"))))  # type: ignore[arg-type]
    asyncio.run(handler(FakeRoute(request=FakeRequest(url="https://evil.com/b"))))  # type: ignore[arg-type]

    assert len(events) == 2
    assert events[0].url == "https://example.com/a"
    assert events[0].allowed is True
    assert events[1].url == "https://evil.com/b"
    assert events[1].allowed is False


def test_on_allowed_override_is_used_instead_of_continue() -> None:
    """Tests swap this in for `route.fulfill(...)` so an 'allowed' decision
    never actually reaches the real network."""
    guard = ScopeGuard(_scope())
    events: list[RuntimeEvent] = []

    async def fulfill_locally(route: FakeRoute) -> None:
        await route.fulfill(status=200, body="ok")

    handler = make_route_handler(guard, events, on_allowed=fulfill_locally)  # type: ignore[arg-type]
    route = FakeRoute(request=FakeRequest(url="https://example.com/a"))

    asyncio.run(handler(route))  # type: ignore[arg-type]

    assert route.fulfilled is True
    assert route.continued is False
