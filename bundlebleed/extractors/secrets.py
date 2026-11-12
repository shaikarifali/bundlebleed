from __future__ import annotations

import base64
import hashlib
import json
import math
import re

from bundlebleed.extractors.patterns import load_secret_patterns
from bundlebleed.models import EntropySecret, Secret

_TOKEN_RE = re.compile(r"[0-9A-Za-z_\-./+]{20,}")
_ENTROPY_THRESHOLD = 4.0
_ENTROPY_CAP = 500


def _shannon(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) for c in set(s)}
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


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


def extract_entropy_secrets(
    content: str, source_url: str, file: str = "", known_hashes: set[str] | None = None
) -> list[EntropySecret]:
    """Second-pass high-entropy token scan — catches unstructured credentials
    missed by known-regex patterns.

    Tokens already matched by the known-regex pass (passed in via `known_hashes`)
    are skipped so the two passes don't overlap in reports.
    Capped at _ENTROPY_CAP results to keep reports readable.
    Never stores plaintext — only the redacted preview and partial hash.
    """
    path = file or source_url
    skip = known_hashes or set()
    lines = content.splitlines()
    results: list[EntropySecret] = []
    seen: set[str] = set()

    for line_no, line in enumerate(lines, 1):
        for m in _TOKEN_RE.finditer(line):
            tok = m.group(0)
            score = _shannon(tok)
            if score < _ENTROPY_THRESHOLD:
                continue
            digest = _partial_hash(tok)
            if digest in skip or digest in seen:
                continue
            seen.add(digest)
            results.append(
                EntropySecret(
                    file=path,
                    line=line_no,
                    entropy_score=round(score, 3),
                    redacted_value=_redact(tok),
                    partial_hash=digest,
                    source_url=source_url,
                )
            )
            if len(results) >= _ENTROPY_CAP:
                return results

    return results
