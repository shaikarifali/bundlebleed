from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Protocol

from bundlebleed.runtime.models import RuntimeEvent
from bundlebleed.scope.guard import ScopeGuard


class RouteRequest(Protocol):
    url: str
    method: str
    resource_type: str


class Route(Protocol):
    @property
    def request(self) -> RouteRequest: ...
    async def abort(self) -> None: ...
    async def continue_(self) -> None: ...


RouteHandler = Callable[[Route], Awaitable[None]]


def make_route_handler(
    guard: ScopeGuard,
    events: list[RuntimeEvent],
    on_allowed: RouteHandler | None = None,
) -> RouteHandler:
    """Build a request handler that checks EVERY request against ScopeGuard
    before it is ever allowed through — including top-level navigations and
    redirects, since Playwright's routing covers those the same as any
    subresource fetch. A denied request is aborted; nothing is sent.

    `on_allowed` defaults to `route.continue_()` (real production
    behavior). Tests override it with a local `route.fulfill(...)` so an
    "allowed" decision never actually reaches the real network.
    """

    async def handle(route: Route) -> None:
        request = route.request
        allowed = guard.allowed(request.url)
        events.append(
            RuntimeEvent(
                url=request.url,
                method=request.method,
                resource_type=request.resource_type,
                allowed=allowed,
            )
        )
        if not allowed:
            await route.abort()
            return
        if on_allowed is not None:
            await on_allowed(route)
        else:
            await route.continue_()

    return handle
