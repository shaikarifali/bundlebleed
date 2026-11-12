from __future__ import annotations

import re

from pydantic import BaseModel, Field

from bundlebleed.models import Endpoint, ParameterFinding

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class ObjectAccessCandidate(BaseModel):
    """Potential BOLA/IDOR or mass-assignment candidate discovered in JS.

    Finding levels (not severity — just how much evidence was found):
      1 = object identifier pattern found in an endpoint path/query
      2 = identifier connected to a named function
      3 = sensitive property also present in the same request construction
      4 = cross-tenant-looking identifiers (tenant/org/account IDs)
    """

    endpoint: str
    identifier: str
    function_name: str | None
    sensitive_properties: list[str] = Field(default_factory=list)
    level: int
    bug_class: str  # "BOLA" | "mass_assignment" | "BFLA"
    source_url: str
    evidence: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

# Object identifier names that suggest per-object authorization is needed
_OBJECT_ID_PATTERNS = re.compile(
    r"""\b(userId|user_id|accountId|account_id|tenantId|tenant_id|
         orgId|org_id|organizationId|organization_id|
         memberId|member_id|invoiceId|invoice_id|
         paymentId|payment_id|documentId|document_id|
         transactionId|transaction_id|orderId|order_id|
         subscriptionId|subscription_id|projectId|project_id|
         customerId|customer_id|clientId|client_id)\b""",
    re.VERBOSE | re.IGNORECASE,
)

# Cross-tenant indicators (higher risk)
_CROSS_TENANT_IDS = frozenset([
    "tenantid", "tenant_id", "orgid", "org_id",
    "organizationid", "organization_id", "accountid", "account_id",
])

# Sensitive properties that shouldn't be mass-assignable
_SENSITIVE_PROPS = re.compile(
    r"""\b(role|isAdmin|is_admin|isOwner|is_owner|
         permissions|admin|staff|superuser|
         approvalStatus|approval_status|verified|isVerified|is_verified|
         balance|creditLimit|credit_limit|
         plan|subscription|tier|
         status|accountStatus|account_status)\b""",
    re.VERBOSE | re.IGNORECASE,
)

# Mass-assignment spread patterns
_SPREAD_PATTERNS = [
    re.compile(r"""\{\s*\.\.\.\s*\w+\s*,\s*\.\.\.\w+"""),           # {...a, ...b}
    re.compile(r"""Object\.assign\s*\(\s*\{\s*\}"""),                 # Object.assign({}, ...)
    re.compile(r"""(?:body|data|payload)\s*[:=]\s*\{\s*\.\.\."""),    # body = {...
    re.compile(r"""(?:formData|form_data|userData)\s*\[['"](\w+)['"]\]\s*="""),  # formData['role'] =
]

# Admin/privileged function-level access patterns
_BFLA_ENDPOINT_RE = re.compile(
    r"""/(?:admin|internal|staff|moderator|superuser|backstage|manage|console)""",
    re.IGNORECASE,
)

# Parameterized path: /resource/:id or /resource/{id} or /resource/123
_PARAMETERIZED_PATH_RE = re.compile(
    r"""/[a-zA-Z_-]+/(?::[\w]+|\{[\w]+\}|\d{3,}|[0-9a-f]{8,})""",
)

# Query string with ID-like param
_ID_QUERY_RE = re.compile(
    r"""[?&]([a-zA-Z_][a-zA-Z0-9_]*)=(?:\d+|[0-9a-f-]{8,})\b""",
)


def _extract_id_from_endpoint(ep_value: str) -> str | None:
    """Find the identifier name from a parameterized endpoint path."""
    m = re.search(r"""/:([a-zA-Z_][a-zA-Z0-9_]*)|\{([a-zA-Z_][a-zA-Z0-9_]*)\}""", ep_value)
    if m:
        return m.group(1) or m.group(2)
    m2 = _ID_QUERY_RE.search(ep_value)
    if m2:
        return m2.group(1)
    if re.search(r"""/\d{3,}""", ep_value):
        return "id"
    return None


def _sensitive_props_in_content(content: str) -> list[str]:
    return list(dict.fromkeys(
        m.group(1) for m in _SENSITIVE_PROPS.finditer(content)
    ))


def _has_spread_pattern(content: str) -> bool:
    return any(pat.search(content) for pat in _SPREAD_PATTERNS)


def analyze_object_authorization(
    endpoints: list[Endpoint],
    parameters: list[ParameterFinding],
    js_content_map: dict[str, str],
) -> list[ObjectAccessCandidate]:
    """Find BOLA/IDOR, mass-assignment, and BFLA candidates from discovered endpoints.

    `js_content_map` maps source_url → JS content for deeper property analysis.
    Pass an empty dict to run with endpoint+parameter data only (shallower, still useful).

    Finding levels:
      1 = parameterized endpoint or ID-shaped query param
      2 = named function mapping found
      3 = sensitive property also in same JS file
      4 = cross-tenant object identifier
    """
    candidates: list[ObjectAccessCandidate] = []
    seen: set[tuple[str, str]] = set()

    param_by_source: dict[str, list[ParameterFinding]] = {}
    for p in parameters:
        param_by_source.setdefault(p.source_url, []).append(p)

    for ep in endpoints:
        ep_val = ep.value
        content = js_content_map.get(ep.source_url, "")

        # --- BOLA / IDOR ---
        identifier = _extract_id_from_endpoint(ep_val)
        if identifier:
            key = (ep_val, identifier)
            if key not in seen:
                seen.add(key)
                func_name = next(
                    (p.function_name for p in param_by_source.get(ep.source_url, []) if p.name.lower() == identifier.lower()),
                    None,
                )
                is_cross_tenant = identifier.lower() in _CROSS_TENANT_IDS
                sensitive_props = _sensitive_props_in_content(content) if content else []
                level = 4 if is_cross_tenant else (3 if sensitive_props else (2 if func_name else 1))
                evidence = [
                    f"Parameterized endpoint: {ep_val}",
                    f"Object identifier: {identifier}",
                ]
                if func_name:
                    evidence.append(f"Consuming function: {func_name}()")
                if sensitive_props:
                    evidence.append(f"Sensitive properties in same file: {sensitive_props[:5]}")
                if is_cross_tenant:
                    evidence.append("Cross-tenant identifier — potential cross-account access")
                candidates.append(
                    ObjectAccessCandidate(
                        endpoint=ep_val,
                        identifier=identifier,
                        function_name=func_name,
                        sensitive_properties=sensitive_props[:10],
                        level=level,
                        bug_class="BOLA",
                        source_url=ep.source_url,
                        evidence=evidence,
                    )
                )

        # --- BFLA (admin/privileged routes) ---
        if _BFLA_ENDPOINT_RE.search(ep_val):
            key = (ep_val, "bfla")
            if key not in seen:
                seen.add(key)
                func_name = next(
                    (p.function_name for p in param_by_source.get(ep.source_url, []) if p.function_name),
                    None,
                )
                candidates.append(
                    ObjectAccessCandidate(
                        endpoint=ep_val,
                        identifier="privileged_path",
                        function_name=func_name,
                        level=2,
                        bug_class="BFLA",
                        source_url=ep.source_url,
                        evidence=[
                            f"Admin/privileged path segment in: {ep_val}",
                            "Verify server-side role enforcement — not just UI hiding",
                        ],
                    )
                )

    # --- Mass assignment (content-level scan) ---
    for source_url, content in js_content_map.items():
        if not _has_spread_pattern(content):
            continue
        props = _sensitive_props_in_content(content)
        if not props:
            continue
        key = (source_url, "mass_assign")
        if key not in seen:
            seen.add(key)
            # Find the endpoint(s) from this source file
            related_ep = next((ep.value for ep in endpoints if ep.source_url == source_url), source_url)
            candidates.append(
                ObjectAccessCandidate(
                    endpoint=related_ep,
                    identifier="spread_pattern",
                    function_name=None,
                    sensitive_properties=props[:10],
                    level=3,
                    bug_class="mass_assignment",
                    source_url=source_url,
                    evidence=[
                        "Object spread / Object.assign detected in request construction",
                        f"Sensitive properties included: {props[:5]}",
                        "Verify server ignores or rejects these properties on update",
                    ],
                )
            )

    return sorted(candidates, key=lambda c: (-c.level, c.endpoint))
