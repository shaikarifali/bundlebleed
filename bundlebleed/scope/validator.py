from __future__ import annotations

from fnmatch import fnmatch
from urllib.parse import urlsplit

from bundlebleed.scope.models import Decision, MatchType, ScopeConfig, ScopeDecision


def _domain_matches_pattern(hostname: str, pattern: str) -> bool:
    """Wildcard convention: a leading '*.' matches the base domain and any subdomain."""
    hostname = hostname.lower()
    pattern = pattern.lower()
    if pattern.startswith("*."):
        base = pattern[2:]
        return hostname == base or hostname.endswith("." + base)
    return hostname == pattern


def extract_hostname(url_or_domain: str) -> str:
    candidate = url_or_domain
    if "://" not in candidate:
        candidate = f"https://{candidate}"
    hostname = urlsplit(candidate).hostname
    return (hostname or url_or_domain).lower()


def extract_path(url_or_domain: str) -> str:
    if "://" not in url_or_domain:
        return "/"
    path = urlsplit(url_or_domain).path
    return path or "/"


def is_in_scope(url_or_domain: str, config: ScopeConfig) -> ScopeDecision:
    hostname = extract_hostname(url_or_domain)
    path = extract_path(url_or_domain)

    for excluded in config.out_of_scope:
        if _domain_matches_pattern(hostname, excluded):
            return ScopeDecision(
                url=url_or_domain,
                decision=Decision.DENY,
                reason=f"out-of-scope: {hostname}",
            )

    matched = False
    for entry in config.in_scope:
        pattern = f"*.{entry.domain}" if entry.match_type == MatchType.WILDCARD else entry.domain
        if _domain_matches_pattern(hostname, pattern):
            matched = True
            break

    if not matched:
        return ScopeDecision(
            url=url_or_domain,
            decision=Decision.DENY,
            reason=f"not in scope: {hostname}",
        )

    for excluded_path in config.excluded_paths:
        if fnmatch(path, excluded_path):
            return ScopeDecision(
                url=url_or_domain,
                decision=Decision.DENY,
                reason=f"excluded path: {path}",
            )

    return ScopeDecision(url=url_or_domain, decision=Decision.ALLOW, reason="in scope")
