from __future__ import annotations

from bundlebleed.history.models import ScanDiff


def has_changes(diff: ScanDiff) -> bool:
    return bool(
        diff.new_endpoints
        or diff.removed_endpoints
        or diff.new_secrets
        or diff.removed_secrets
        or diff.new_subdomains
        or diff.removed_subdomains
        or diff.access_control_regressions
    )


def format_slack_payload(diff: ScanDiff, target: str) -> dict[str, str]:
    """Slack/Discord both accept this minimal {"text": ...} shape. Built
    only from already-redacted ScanDiff data — secrets appear as
    "type:partial_hash" labels, never a value."""
    lines = [f"*BundleBleed*: changes detected for `{target}`"]

    if diff.access_control_regressions:
        targets = ", ".join(f"`{v}`" for v in diff.access_control_regressions)
        lines.append(
            f":rotating_light: *{len(diff.access_control_regressions)} access-control "
            f"regression(s)* — reachable without auth now, required a session last scan: "
            f"{targets}"
        )
    if diff.new_endpoints:
        lines.append(f"+{len(diff.new_endpoints)} new endpoint(s)")
    if diff.removed_endpoints:
        lines.append(f"-{len(diff.removed_endpoints)} removed endpoint(s)")
    if diff.new_secrets:
        lines.append(f"+{len(diff.new_secrets)} new secret(s) (type:hash only)")
    if diff.removed_secrets:
        lines.append(f"-{len(diff.removed_secrets)} removed secret(s)")
    if diff.new_subdomains:
        subdomains = ", ".join(diff.new_subdomains)
        lines.append(f"+{len(diff.new_subdomains)} new subdomain(s): {subdomains}")
    if diff.removed_subdomains:
        lines.append(f"-{len(diff.removed_subdomains)} removed subdomain(s)")

    return {"text": "\n".join(lines)}
