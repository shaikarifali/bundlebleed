from __future__ import annotations

import re
from pathlib import Path

from bundlebleed.models import ScanResult

_HEADER = """\
#!/usr/bin/env bash
# BundleBleed — curl verification sheet
# =============================================================================
# Replace $BUNDLEBLEED_COOKIE with your session cookie / Authorization header.
# MANUAL FIRING REQUIRED — this script sends nothing on its own.
# Usage:  bash curls.sh 2>&1 | tee curls-output.txt
#
# Each _curl() prints only the HTTP status code.  Replace REPLACE_ID / REPLACE_VAL
# with real values from the app before firing.
# =============================================================================

COOKIE="${BUNDLEBLEED_COOKIE:-}"
AUTH="${BUNDLEBLEED_AUTH:-}"
BASE="${BUNDLEBLEED_BASE:-REPLACE_BASE}"

_curl() {
  curl -s -o /dev/null -w "%{http_code}" \\
    ${AUTH:+-H "Authorization: $AUTH"} \\
    ${COOKIE:+-H "Cookie: $COOKIE"} \\
    "$@"
  echo
}
"""

# Identifier names we substitute with REPLACE_ID in parameterized paths
_ID_PLACEHOLDER_RE = re.compile(
    r"""/:([a-zA-Z_][a-zA-Z0-9_]*)|\{([a-zA-Z_][a-zA-Z0-9_]*)\}""",
)
_NUMERIC_PATH_RE = re.compile(r"""(/)\d{3,}""")


def _make_path_safe(endpoint_value: str, identifier: str = "") -> str:
    """Replace parameterized path segments with REPLACE_ID placeholder."""
    path = _ID_PLACEHOLDER_RE.sub("/REPLACE_ID", endpoint_value)
    path = _NUMERIC_PATH_RE.sub(r"\1REPLACE_ID", path)
    if identifier:
        # Also replace query param value
        path = re.sub(
            rf"([?&]{re.escape(identifier)}=)[^\s&]*",
            r"\1REPLACE_VAL",
            path,
        )
    return path


def render_curls_sh(result: ScanResult) -> str:
    """Generate a bash verification sheet — one curl per notable endpoint.

    Sections (descending priority):
    1. BOLA/IDOR candidates (highest severity — parameterized endpoints, tenant IDs)
    2. BFLA candidates (admin/internal/privileged routes)
    3. Auth-required endpoints (try unauthenticated too)
    4. Unauthenticated endpoints (look for sensitive data returned without auth)
    5. GraphQL endpoints
    6. Remaining live endpoints (capped at 50)
    """
    r = result.normalized()
    lines: list[str] = [_HEADER]

    # 1 — BOLA / IDOR
    bola = [c for c in r.object_access_candidates if c.bug_class == "BOLA"]
    if bola:
        lines.append("# ── BOLA / IDOR candidates (level descending) ──────────────────────────────")
        for c in sorted(bola, key=lambda x: -x.level):
            safe_path = _make_path_safe(c.endpoint, c.identifier)
            lines.append(f"# Level {c.level} | identifier: {c.identifier}")
            if c.function_name:
                lines.append(f"# function: {c.function_name}()")
            lines.append(f'_curl "$BASE{safe_path}"')
            lines.append("")

    # 2 — BFLA
    bfla = [c for c in r.object_access_candidates if c.bug_class == "BFLA"]
    if bfla:
        lines.append("# ── BFLA / privileged routes (verify server-side enforcement) ──────────────")
        for c in bfla:
            lines.append(f"# BFLA: {c.endpoint}")
            lines.append(f'_curl "$BASE{c.endpoint}"')
            lines.append("")

    # 3 — Auth-required endpoints
    auth_eps = [e for e in r.endpoints if e.tag == "auth-required"][:30]
    if auth_eps:
        lines.append("# ── Auth-required endpoints (try WITHOUT cookie first) ─────────────────────")
        for e in auth_eps:
            lines.append(f"# {e.pattern_name}")
            safe = _make_path_safe(e.value)
            lines.append(f'_curl "$BASE{safe}"')
            lines.append("")

    # 4 — Unauthenticated endpoints
    unauthed_eps = [e for e in r.endpoints if e.tag == "unauthed"][:30]
    if unauthed_eps:
        lines.append("# ── Unauthenticated endpoints (look for sensitive data without auth) ────────")
        for e in unauthed_eps:
            safe = _make_path_safe(e.value)
            lines.append(f'_curl "$BASE{safe}"')
            lines.append("")

    # 5 — GraphQL endpoints
    graphql_endpoints = list(
        dict.fromkeys(op.endpoint for op in r.graphql_operations if op.endpoint)
    )
    if graphql_endpoints:
        lines.append("# ── GraphQL endpoints (try introspection query) ────────────────────────────")
        introspection = '{"query":"{__schema{types{name}}}"}'
        for gql_ep in graphql_endpoints[:5]:
            lines.append(f"# GraphQL endpoint: {gql_ep}")
            lines.append(
                f"_curl -X POST -H 'Content-Type: application/json' "
                f"-d '{introspection}' \"$BASE{gql_ep}\""
            )
            lines.append("")

    # 6 — Remaining live/historical endpoints (cap at 50)
    tagged_set = {c.endpoint for c in r.object_access_candidates}
    tagged_set |= {e.value for e in r.endpoints if e.tag in ("auth-required", "unauthed")}
    remaining = [e for e in r.endpoints if e.value not in tagged_set and e.tag in ("live", "historical")][:50]
    if remaining:
        lines.append("# ── All other endpoints ────────────────────────────────────────────────────")
        for e in remaining:
            safe = _make_path_safe(e.value)
            lines.append(f'_curl "$BASE{safe}"')
        lines.append("")

    return "\n".join(lines)


def write_curls_sh(result: ScanResult, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "curls.sh"
    path.write_text(render_curls_sh(result))
    path.chmod(0o755)
    return path
