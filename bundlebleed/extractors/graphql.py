from __future__ import annotations

import re

from pydantic import BaseModel, Field


class GraphQLOperation(BaseModel):
    """A GraphQL query, mutation, or subscription extracted from JS."""

    op_type: str  # "query" | "mutation" | "subscription" | "unknown"
    op_name: str
    variables: list[str] = Field(default_factory=list)
    fields: list[str] = Field(default_factory=list)
    endpoint: str
    file: str
    line: int
    source_url: str
    is_persisted: bool = False
    persisted_hash: str = ""


# --- detection patterns ---

# Client library imports / initializations
_CLIENT_LIBS = [
    re.compile(r"\bapolloClient\b|\bApolloClient\b|\bnew ApolloClient\b"),
    re.compile(r"\bcreateClient\b.*graphql|graphql.*\bcreateClient\b", re.IGNORECASE),
    re.compile(r"\burql\b|\bcreateClient\b.*urql|from ['\"]urql['\"]"),
    re.compile(r"\bgraphql-request\b|from ['\"]graphql-request['\"]"),
    re.compile(r"\bRelayEnvironment\b|\bRelayNetworkLayer\b"),
    re.compile(r"\bgql`|graphql`"),
]

# Endpoint detection
_ENDPOINT_RE = re.compile(
    r"""(?:uri|endpoint|url)\s*[:=]\s*['"]((?:https?://[^'"]+)?/graphql[^'"]*)['"]\s*""",
    re.IGNORECASE,
)
_ENDPOINT_GENERIC_RE = re.compile(
    r"""fetch\s*\(\s*['"]((?:https?://[^'"]+)?/graphql[^'"]*)['"]\s*""",
    re.IGNORECASE,
)

# Operation body detection: gql`...` or graphql`...` template literals
_GQL_TEMPLATE_RE = re.compile(r"""(?:gql|graphql)\s*`(.*?)`""", re.DOTALL)
# Inline query/mutation strings
_OPERATION_STR_RE = re.compile(
    r"""(?:query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:\([^)]*\))?\s*\{""",
    re.DOTALL,
)
# Persisted queries: APQ hash mappings
_PERSISTED_RE = re.compile(
    r"""(?:operationId|queryId|persistedQuery|sha256Hash)\s*[:=]\s*['"](sha256:)?([0-9a-f]{64})['"]\s*""",
    re.IGNORECASE,
)
# Variable names inside operations
_VAR_RE = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)\s*:")
# Field names (top-level)
_FIELD_RE = re.compile(r"\b([a-z][A-Za-z0-9_]*)\s*(?:\([^)]*\))?\s*\{")

_SENSITIVE_OP_KEYWORDS = frozenset([
    "admin", "delete", "remove", "destroy", "transfer", "refund", "approve",
    "reject", "ban", "unban", "promote", "demote", "impersonate", "revoke",
    "purge", "reset", "grant", "revoke", "elevate",
])
_SENSITIVE_FIELD_KEYWORDS = frozenset([
    "password", "secret", "token", "apikey", "privatekey", "ssn", "dob",
    "creditcard", "cvv", "bankaccount", "isadmin", "role", "permissions",
    "salary", "internalid",
])


def _line_number(content: str, pos: int) -> int:
    return content.count("\n", 0, pos) + 1


def _extract_variables(operation_body: str) -> list[str]:
    return list(dict.fromkeys(_VAR_RE.findall(operation_body)))


def _extract_fields(operation_body: str) -> list[str]:
    return list(dict.fromkeys(m.group(1) for m in _FIELD_RE.finditer(operation_body)))


def _detect_endpoint(content: str) -> str:
    for pat in [_ENDPOINT_RE, _ENDPOINT_GENERIC_RE]:
        m = pat.search(content)
        if m:
            return m.group(1)
    return "/graphql"


def detect_graphql_client(content: str) -> bool:
    """True if any known GraphQL client library is present in this file."""
    return any(pat.search(content) for pat in _CLIENT_LIBS)


def extract_graphql_operations(
    content: str, source_url: str, file: str = ""
) -> list[GraphQLOperation]:
    """Extract GraphQL operations from JS/TS source.

    Covers:
    - gql`` / graphql`` template literals (Apollo, urql, etc.)
    - Inline query/mutation/subscription strings
    - Persisted query hashes mapped to operation documents
    - Variable and field extraction for BOLA/mass-assign signal

    Does NOT send any requests — pure static extraction.
    """
    path = file or source_url
    endpoint = _detect_endpoint(content)
    seen: set[str] = set()
    results: list[GraphQLOperation] = []

    def _add(op_type: str, op_name: str, body: str, line_no: int, persisted_hash: str = "") -> None:
        key = (op_type, op_name)
        if key in seen:
            return
        seen.add(key)
        variables = _extract_variables(body)
        fields = _extract_fields(body)
        results.append(
            GraphQLOperation(
                op_type=op_type,
                op_name=op_name,
                variables=variables,
                fields=fields,
                endpoint=endpoint,
                file=path,
                line=line_no,
                source_url=source_url,
                is_persisted=bool(persisted_hash),
                persisted_hash=persisted_hash,
            )
        )

    # gql`...` / graphql`...` template literals
    for m in _GQL_TEMPLATE_RE.finditer(content):
        body = m.group(1)
        line_no = _line_number(content, m.start())
        for op_m in _OPERATION_STR_RE.finditer(body):
            op_type = op_m.group(0).split()[0].lower()
            op_name = op_m.group(1)
            _add(op_type, op_name, body, line_no)
        # Template with no named operation
        if not _OPERATION_STR_RE.search(body) and body.strip():
            _add("unknown", f"anonymous_{line_no}", body, line_no)

    # Inline operation strings not in template literals
    for m in _OPERATION_STR_RE.finditer(content):
        op_type = m.group(0).split()[0].lower()
        op_name = m.group(1)
        line_no = _line_number(content, m.start())
        _add(op_type, op_name, content[m.start() : m.start() + 500], line_no)

    # Persisted query hashes
    for m in _PERSISTED_RE.finditer(content):
        hash_val = m.group(2)
        line_no = _line_number(content, m.start())
        key = ("persisted", hash_val[:16])
        if key not in seen:
            seen.add(key)
            results.append(
                GraphQLOperation(
                    op_type="persisted",
                    op_name=f"persisted_{hash_val[:16]}",
                    variables=[],
                    fields=[],
                    endpoint=endpoint,
                    file=path,
                    line=line_no,
                    source_url=source_url,
                    is_persisted=True,
                    persisted_hash=hash_val,
                )
            )

    return results


def graphql_risk_flags(ops: list[GraphQLOperation]) -> list[str]:
    """Return human-readable risk signals from a list of operations.

    These are investigation leads, not confirmed vulnerabilities.
    """
    flags: list[str] = []
    for op in ops:
        name_lower = op.op_name.lower()
        if op.op_type == "mutation" and any(kw in name_lower for kw in _SENSITIVE_OP_KEYWORDS):
            flags.append(
                f"Sensitive mutation '{op.op_name}' at {op.file}:{op.line} "
                f"— verify authorization enforcement"
            )
        sensitive_vars = [v for v in op.variables if v.lower().rstrip("s") in {"userid", "accountid", "tenantid", "organizationid", "memberid"}]
        if sensitive_vars:
            flags.append(
                f"Operation '{op.op_name}' takes object-owner IDs: {sensitive_vars} "
                f"— potential BOLA"
            )
        sensitive_fields = [f for f in op.fields if f.lower() in _SENSITIVE_FIELD_KEYWORDS]
        if sensitive_fields:
            flags.append(
                f"Operation '{op.op_name}' selects sensitive fields: {sensitive_fields}"
            )
    return flags
