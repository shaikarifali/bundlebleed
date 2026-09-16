from __future__ import annotations

import dns.exception
import dns.resolver

from bundlebleed.models import DanglingCnameFinding

# Service CNAME suffixes with a documented history of dangling-record
# takeover -- the same set every established scanner (subjack, tko-subs,
# nuclei's subdomain-takeover templates) checks against. Presence alone is
# NOT proof of takeover: it only means the CNAME target belongs to a
# service where an unclaimed record is possible.
#
# Deliberately DNS-only. This tool never makes an HTTP request to the CNAME
# target to "confirm" claimability -- that host is, by definition, outside
# the declared scope, so confirming it is left to a human via the drafted
# proposed_test (check the provider's own UI/CLI, or fetch the target
# yourself and look for a known "no such app"/"bucket does not exist" page).
_TAKEOVER_PRONE_CNAME_SUFFIXES = (
    "github.io",
    "herokuapp.com",
    "herokudns.com",
    "s3.amazonaws.com",
    "s3-website",
    "azurewebsites.net",
    "cloudapp.net",
    "cloudapp.azure.com",
    "trafficmanager.net",
    "cloudfront.net",
    "fastly.net",
    "readme.io",
    "surge.sh",
    "wpengine.com",
    "pantheonsite.io",
    "zendesk.com",
    "statuspage.io",
    "helpscoutdocs.com",
    "wordpress.com",
    "tumblr.com",
    "myshopify.com",
    "unbouncepages.com",
    "webflow.io",
    "bitbucket.io",
    "ghost.io",
    "netlify.app",
    "vercel.app",
    "pages.dev",
    "firebaseapp.com",
    "web.app",
)

_DNS_TIMEOUT_SECONDS = 5.0


def resolve_cname(domain: str) -> str | None:
    """Resolve one hop of `domain`'s CNAME record. Returns None on any
    resolution failure (NXDOMAIN, no CNAME record present, timeout, ...)
    -- a failed lookup is data, not an error this tool needs to surface,
    since most domains simply don't have a CNAME at all."""
    try:
        answer = dns.resolver.resolve(
            domain, "CNAME", lifetime=_DNS_TIMEOUT_SECONDS, raise_on_no_answer=False
        )
    except dns.exception.DNSException:
        return None
    if answer.rrset is None or len(answer.rrset) == 0:
        return None
    return str(answer.rrset[0].target).rstrip(".")


def check_dangling_cname(domain: str) -> DanglingCnameFinding | None:
    """DNS-only takeover-candidate check for a single domain. See module
    docstring: this never contacts the CNAME target itself."""
    target = resolve_cname(domain)
    if target is None:
        return None
    target_lower = target.lower()
    for suffix in _TAKEOVER_PRONE_CNAME_SUFFIXES:
        if target_lower.endswith(suffix):
            return DanglingCnameFinding(domain=domain, cname_target=target, service_hint=suffix)
    return None


def check_dangling_cnames(domains: list[str]) -> list[DanglingCnameFinding]:
    """Check each of `domains` in turn. Sequential, not concurrent -- this
    runs at most once per unique discovered subdomain per scan, so
    parallelizing isn't worth the added complexity."""
    findings = []
    for domain in domains:
        finding = check_dangling_cname(domain)
        if finding is not None:
            findings.append(finding)
    return findings
