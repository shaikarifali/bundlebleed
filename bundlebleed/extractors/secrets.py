from __future__ import annotations

import base64
import hashlib
import json

from bundlebleed.extractors.patterns import load_secret_patterns
from bundlebleed.models import Secret


def _redact(value: str) -> str:
    """Keep enough of the value to be recognizable in a report, never enough
    to be usable (CLAUDE.md Invariant 7 — no live credential in plaintext)."""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}{'*' * (len(value) - 8)}{value[-4:]}"


def _partial_hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:12]


def _jwt_header_alg(token: str) -> str | None:
    """Decode a JWT's header segment and return its 'alg' value, or None if
    it can't be parsed as one — never raises, the token is attacker-
    controlled content from a third-party scan target."""
    try:
        header_b64 = token.split(".", 1)[0]
        padded = header_b64 + "=" * (-len(header_b64) % 4)
        header = json.loads(base64.urlsafe_b64decode(padded))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(header, dict):
        return None
    alg = header.get("alg")
    return str(alg) if alg is not None else None


def extract_secrets(content: str, source_url: str) -> list[Secret]:
    """Regex-extract candidate secrets from JS content.

    The raw matched value is never returned or stored — only its type,
    a redacted preview, and a partial hash for correlation/dedup. Every
    matched JWT is additionally decoded (header only, never the payload
    signature) to check for `"alg":"none"` — a direct authentication-bypass
    primitive, reported as its own distinct, higher-severity secret type
    alongside the plain 'jwt_token' match.
    """
    secrets: list[Secret] = []
    seen_hashes: set[str] = set()
    seen_alg_none_hashes: set[str] = set()

    for pattern in load_secret_patterns():
        for match in pattern.regex.finditer(content):
            value = match.group(0)
            digest = _partial_hash(value)
            if digest in seen_hashes:
                continue
            seen_hashes.add(digest)
            secrets.append(
                Secret(
                    secret_type=pattern.name,
                    severity=pattern.severity,
                    redacted_value=_redact(value),
                    partial_hash=digest,
                    source_url=source_url,
                )
            )

            if pattern.name == "jwt_token" and digest not in seen_alg_none_hashes:
                alg = _jwt_header_alg(value)
                if alg is not None and alg.strip().lower() == "none":
                    seen_alg_none_hashes.add(digest)
                    secrets.append(
                        Secret(
                            secret_type="jwt_alg_none",
                            severity="critical",
                            redacted_value=_redact(value),
                            partial_hash=digest,
                            source_url=source_url,
                        )
                    )

    return secrets
