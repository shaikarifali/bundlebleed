from __future__ import annotations

import re

from pydantic import BaseModel, Field


class AuthFinding(BaseModel):
    """An authentication/authorization configuration signal extracted from JS."""

    finding_type: str
    detail: str
    severity_candidate: str  # "critical" | "high" | "medium" | "low" | "info"
    file: str
    line: int
    source_url: str


# --- JWT patterns ---

_JWT_DECODE_NO_VERIFY_RE = re.compile(
    r"""(?:jwt_decode|jwtDecode|decode)\s*\(\s*[^,)]+\s*\)(?!\s*,\s*\{)""",
    re.IGNORECASE,
)
_JWT_ALG_RE = re.compile(r"""(?:algorithms?|alg)\s*:\s*['"]([\w-]+)['"]""", re.IGNORECASE)
_JWT_NONE_RE = re.compile(r"""(?:algorithms?|alg)\s*:\s*['"]none['"]""", re.IGNORECASE)
_JWT_KID_RE = re.compile(r"""\bkid\b.*:\s*['"]([\w./\-]+)['"]""", re.IGNORECASE)
_JWT_JKU_RE = re.compile(r"""\bjku\b\s*:\s*['"](https?://[^'"]+)['"]""", re.IGNORECASE)
_JWT_X5U_RE = re.compile(r"""\bx5u\b\s*:\s*['"](https?://[^'"]+)['"]""", re.IGNORECASE)

# Token storage patterns
_LOCALSTORAGE_TOKEN_RE = re.compile(
    r"""localStorage\s*\.\s*setItem\s*\(\s*['"]([^'"]*(?:token|auth|jwt|key|refresh)[^'"]*)['"]\s*,""",
    re.IGNORECASE,
)
_SESSION_STORAGE_TOKEN_RE = re.compile(
    r"""sessionStorage\s*\.\s*setItem\s*\(\s*['"]([^'"]*(?:token|auth|jwt|key)[^'"]*)['"]\s*,""",
    re.IGNORECASE,
)
_URL_TOKEN_RE = re.compile(
    r"""(?:location|window\.location)\s*\.\s*(?:href|search|hash).*(?:token|access_token|id_token)""",
    re.IGNORECASE,
)
_CONSOLE_TOKEN_RE = re.compile(
    r"""console\s*\.\s*log\s*\([^)]*(?:token|auth|jwt|credential|password)[^)]*\)""",
    re.IGNORECASE,
)

# OAuth patterns
_OAUTH_ENDPOINT_RE = re.compile(
    r"""['"]([^'"]+(?:authorize|oauth|auth|token|callback)[^'"]*)['"]\s*""",
    re.IGNORECASE,
)
_PKCE_RE = re.compile(r"""\bcode_verifier\b|\bcode_challenge\b|\bPKCE\b""", re.IGNORECASE)
_STATE_PARAM_RE = re.compile(r"""\bstate\s*[:=]\s*['"]([\w./\-]+)['"]|\bstate\b""", re.IGNORECASE)
_NONCE_RE = re.compile(r"""\bnonce\b""", re.IGNORECASE)
_REDIRECT_URI_DYNAMIC_RE = re.compile(
    r"""redirect_uri\s*[:=+]\s*(?:window\.location|location\.href|location\.origin|[^'"]{5,})""",
    re.IGNORECASE,
)
_IMPLICIT_FLOW_RE = re.compile(
    r"""response_type\s*[:=]\s*['"]token['"]""",
    re.IGNORECASE,
)

# Refresh token exposure
_REFRESH_LOCALSTORAGE_RE = re.compile(
    r"""localStorage\s*\.\s*setItem\s*\(\s*['"][^'"]*refresh[^'"]*['"]\s*,""",
    re.IGNORECASE,
)


def _line_number(content: str, pos: int) -> int:
    return content.count("\n", 0, pos) + 1


def extract_auth_findings(
    content: str, source_url: str, file: str = ""
) -> list[AuthFinding]:
    """Extract authentication and authorization configuration signals from JS.

    Covers:
    - JWT decode-without-verify patterns
    - alg:none and algorithm confusion signals
    - Unsafe token storage (localStorage, sessionStorage, URL fragments)
    - OAuth misconfiguration: missing PKCE, missing state, implicit flow,
      dynamic redirect_uri construction
    - Refresh token in accessible storage

    Every finding is a manual-verification lead, not a confirmed vulnerability.
    The JWT decode check specifically: a frontend library decoding a token for
    display does NOT mean the backend skips verification.
    """
    path = file or source_url
    findings: list[AuthFinding] = []
    seen: set[tuple[str, int]] = set()

    def _add(finding_type: str, detail: str, severity: str, line_no: int) -> None:
        key = (finding_type, line_no)
        if key in seen:
            return
        seen.add(key)
        findings.append(
            AuthFinding(
                finding_type=finding_type,
                detail=detail,
                severity_candidate=severity,
                file=path,
                line=line_no,
                source_url=source_url,
            )
        )

    # JWT decode without verify
    for m in _JWT_DECODE_NO_VERIFY_RE.finditer(content):
        _add(
            "jwt_decode_no_verify",
            f"JWT decoded without verification options: `{m.group(0)[:80]}`",
            "medium",
            _line_number(content, m.start()),
        )

    # alg:none
    for m in _JWT_NONE_RE.finditer(content):
        _add(
            "jwt_alg_none",
            "JWT algorithm explicitly set to 'none' — authentication bypass primitive if server accepts it",
            "critical",
            _line_number(content, m.start()),
        )

    # Dangerous key-reference headers (kid/jku/x5u — key confusion / SSRF)
    for pat, finding_type, severity in [
        (_JWT_JKU_RE, "jwt_jku_reference", "high"),
        (_JWT_X5U_RE, "jwt_x5u_reference", "high"),
        (_JWT_KID_RE, "jwt_kid_reference", "medium"),
    ]:
        for m in pat.finditer(content):
            _add(
                finding_type,
                f"JWT header references external key: `{m.group(0)[:80]}`",
                severity,
                _line_number(content, m.start()),
            )

    # Unsafe token storage
    for m in _LOCALSTORAGE_TOKEN_RE.finditer(content):
        key_name = m.group(1)
        is_refresh = "refresh" in key_name.lower()
        _add(
            "token_in_localstorage",
            f"{'Refresh' if is_refresh else 'Auth'} token stored in localStorage key '{key_name}' — XSS-stealable",
            "high" if is_refresh else "medium",
            _line_number(content, m.start()),
        )

    for m in _SESSION_STORAGE_TOKEN_RE.finditer(content):
        _add(
            "token_in_sessionstorage",
            f"Token stored in sessionStorage key '{m.group(1)}'",
            "low",
            _line_number(content, m.start()),
        )

    for m in _URL_TOKEN_RE.finditer(content):
        _add(
            "token_in_url",
            "Token passed via URL/fragment — may appear in logs, referrer headers, history",
            "medium",
            _line_number(content, m.start()),
        )

    for m in _CONSOLE_TOKEN_RE.finditer(content):
        _add(
            "token_logged",
            f"Credential/token passed to console.log: `{m.group(0)[:80]}`",
            "medium",
            _line_number(content, m.start()),
        )

    # OAuth signals
    if _IMPLICIT_FLOW_RE.search(content):
        m = _IMPLICIT_FLOW_RE.search(content)
        _add(
            "oauth_implicit_flow",
            "OAuth implicit flow (response_type=token) — deprecated, token exposed in URL fragment",
            "medium",
            _line_number(content, m.start()),  # type: ignore[union-attr]
        )

    if _REDIRECT_URI_DYNAMIC_RE.search(content):
        m = _REDIRECT_URI_DYNAMIC_RE.search(content)
        _add(
            "oauth_dynamic_redirect_uri",
            "OAuth redirect_uri constructed dynamically — potential open redirect or authorization code theft",
            "high",
            _line_number(content, m.start()),  # type: ignore[union-attr]
        )

    has_pkce = bool(_PKCE_RE.search(content))
    has_state = bool(_STATE_PARAM_RE.search(content))
    has_nonce = bool(_NONCE_RE.search(content))

    # Only flag missing state/PKCE if there's actual OAuth activity
    has_oauth = bool(_OAUTH_ENDPOINT_RE.search(content)) or _IMPLICIT_FLOW_RE.search(content)
    if has_oauth and not has_state:
        _add(
            "oauth_missing_state",
            "OAuth flow detected but no 'state' parameter found — potential CSRF on authorization",
            "medium",
            1,
        )
    if has_oauth and not has_pkce:
        _add(
            "oauth_missing_pkce",
            "OAuth flow without PKCE — authorization code interception risk for public clients",
            "low",
            1,
        )

    # Refresh token in localStorage
    for m in _REFRESH_LOCALSTORAGE_RE.finditer(content):
        _add(
            "refresh_token_in_localstorage",
            "Refresh token stored in localStorage — persistent XSS impact (long-lived access)",
            "high",
            _line_number(content, m.start()),
        )

    return findings
