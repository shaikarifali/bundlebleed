from __future__ import annotations

from bundlebleed.history.models import ScanDiff
from bundlebleed.models import ScanResult


def _auth_gated_endpoint_values(result: ScanResult) -> set[str]:
    """Endpoint values only ever seen coming from a bundle that required an
    authenticated session to reach."""
    auth_only_urls = set(result.auth_only_js_urls)
    return {e.value for e in result.endpoints if e.source_url in auth_only_urls}


def _unauth_endpoint_values(result: ScanResult) -> set[str]:
    auth_only_urls = set(result.auth_only_js_urls)
    return {e.value for e in result.endpoints if e.source_url not in auth_only_urls}


def compute_scan_diff(previous: ScanResult, current: ScanResult) -> ScanDiff:
    """Compare two normalized scans of the same target. Pure computation —
    never fetches anything, never mutates either input."""
    previous = previous.normalized()
    current = current.normalized()

    prev_endpoints = {e.value for e in previous.endpoints}
    curr_endpoints = {e.value for e in current.endpoints}
    prev_secrets = {f"{s.secret_type}:{s.partial_hash}" for s in previous.secrets}
    curr_secrets = {f"{s.secret_type}:{s.partial_hash}" for s in current.secrets}
    prev_subdomains = {s.domain for s in previous.subdomains}
    curr_subdomains = {s.domain for s in current.subdomains}

    # An endpoint that used to be reachable only via an authenticated bundle
    # and now shows up from an unauthenticated one: access control regressed.
    access_control_regressions = sorted(
        _auth_gated_endpoint_values(previous) & _unauth_endpoint_values(current)
    )

    return ScanDiff(
        previous_scan_run_id=previous.scan_run_id,
        previous_started_at=previous.started_at,
        new_endpoints=sorted(curr_endpoints - prev_endpoints),
        removed_endpoints=sorted(prev_endpoints - curr_endpoints),
        new_secrets=sorted(curr_secrets - prev_secrets),
        removed_secrets=sorted(prev_secrets - curr_secrets),
        new_subdomains=sorted(curr_subdomains - prev_subdomains),
        removed_subdomains=sorted(prev_subdomains - curr_subdomains),
        access_control_regressions=access_control_regressions,
    )
