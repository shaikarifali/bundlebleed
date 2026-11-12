from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import structlog

from bundlebleed.scope.models import Decision, ScopeConfig, ScopeDecision
from bundlebleed.scope.validator import is_in_scope

logger = structlog.get_logger(__name__)


class ScopeGuard:
    """The single choke point every outbound URL/domain must pass through.

    No collector, extractor, or verifier may act on a target URL without calling
    `check()` (or `allowed()`/`filter_allowed()`) first. Every decision — ALLOW
    or DENY — is logged and appended to the audit log.
    """

    def __init__(
        self,
        config: ScopeConfig,
        audit_log_path: Path | None = None,
        scan_run_id: str | None = None,
    ) -> None:
        self._config = config
        self._audit_log_path = audit_log_path
        self._scan_run_id = scan_run_id

    def check(self, url_or_domain: str) -> ScopeDecision:
        decision = is_in_scope(url_or_domain, self._config)
        self._audit(decision)
        return decision

    def allowed(self, url_or_domain: str) -> bool:
        return self.check(url_or_domain).decision == Decision.ALLOW

    def filter_allowed(self, urls: list[str]) -> list[str]:
        return [u for u in urls if self.allowed(u)]

    def _audit(self, decision: ScopeDecision) -> None:
        log = logger.bind(scan_run_id=self._scan_run_id)
        if decision.decision == Decision.ALLOW:
            log.info("scope_guard.allow", url=decision.url, reason=decision.reason)
        else:
            log.info("scope_guard.deny", url=decision.url, reason=decision.reason)

        if self._audit_log_path is not None:
            row = {
                "scan_run_id": self._scan_run_id,
                "timestamp": datetime.now(UTC).isoformat(),
                "url": decision.url,
                "decision": decision.decision.value,
                "reason": decision.reason,
            }
            self._audit_log_path.parent.mkdir(parents=True, exist_ok=True)
            with self._audit_log_path.open("a") as f:
                f.write(json.dumps(row) + "\n")
