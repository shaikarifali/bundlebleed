from __future__ import annotations

from typing import Any

import httpx
import structlog

logger = structlog.get_logger(__name__)


async def post_webhook(
    url: str, payload: dict[str, Any], client: httpx.AsyncClient | None = None
) -> bool:
    """POST a notification to a user-supplied webhook URL (Slack/Discord-
    compatible). This is NOT a target request: the destination is the
    operator's own notification channel, not part of the scanned target's
    scope, so it is deliberately never routed through ScopeGuard.

    Never raises — returns True on a 2xx response, False otherwise.
    """
    owns_client = client is None
    http_client = client or httpx.AsyncClient(timeout=10.0)
    try:
        response = await http_client.post(url, json=payload)
    except httpx.HTTPError as exc:
        logger.warning("webhook.request_failed", error=str(exc))
        return False
    finally:
        if owns_client:
            await http_client.aclose()

    if response.status_code // 100 != 2:
        logger.warning("webhook.non_2xx", status=response.status_code)
        return False
    return True
