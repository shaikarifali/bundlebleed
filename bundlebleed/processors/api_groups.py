from __future__ import annotations

import re

from bundlebleed.models import ApiGroup, Endpoint

_VERSION_RE = re.compile(r"/v(\d+)/")

_GROUP_KEYWORDS: dict[str, list[str]] = {
    "auth": ["login", "logout", "register", "token", "oauth", "sso", "session", "password", "reset", "signin", "signup", "verify", "confirm", "mfa", "2fa"],
    "user": ["user", "account", "profile", "me", "member", "subscriber", "identity", "person"],
    "admin": ["admin", "staff", "internal", "manage", "console", "superuser", "moderator", "backstage", "dashboard", "panel", "control"],
    "billing": ["pay", "billing", "invoice", "subscription", "checkout", "stripe", "plan", "pricing", "charge", "refund", "wallet", "payment"],
    "search": ["search", "query", "find", "suggest", "autocomplete", "lookup", "filter", "sort"],
    "debug": ["debug", "test", "health", "ping", "status", "metrics", "monitor", "diag", "trace", "log", "echo"],
    "upload": ["upload", "file", "attachment", "media", "image", "document", "asset", "storage"],
    "notification": ["notification", "alert", "email", "sms", "push", "message", "inbox", "webhook"],
}


def _classify(path: str) -> str:
    lower = path.lower()
    for group, keywords in _GROUP_KEYWORDS.items():
        if any(kw in lower for kw in keywords):
            return group
    return "general"


def _api_version(path: str) -> int | None:
    m = _VERSION_RE.search(path)
    return int(m.group(1)) if m else None


def group_endpoints(endpoints: list[Endpoint]) -> list[ApiGroup]:
    """Cluster endpoints by functional area and flag old API versions.

    When /api/v1/X and /api/v2/X both exist, v1 is flagged as a
    potentially_unlinked_old_version — these endpoints often have weaker
    authorization than their current-version counterparts.
    """
    buckets: dict[str, list[str]] = {g: [] for g in [*_GROUP_KEYWORDS, "general", "api"]}

    for ep in endpoints:
        path = ep.value
        if "/api/" in path.lower() and _classify(path) == "general":
            group = "api"
        else:
            group = _classify(path)
        buckets[group].append(path)

    path_set = {ep.value for ep in endpoints}
    old_versions: dict[str, list[str]] = {g: [] for g in buckets}

    for group, paths in buckets.items():
        for path in paths:
            ver = _api_version(path)
            if ver is None:
                continue
            newer = _VERSION_RE.sub(f"/v{ver + 1}/", path)
            if newer in path_set:
                old_versions[group].append(path)

    result: list[ApiGroup] = []
    for group, paths in buckets.items():
        if not paths:
            continue
        result.append(
            ApiGroup(
                group_name=group,
                endpoints=sorted(set(paths)),
                old_versions=sorted(set(old_versions[group])),
            )
        )

    return sorted(result, key=lambda g: g.group_name)
