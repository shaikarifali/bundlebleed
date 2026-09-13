from __future__ import annotations

from bundlebleed.models import CorsMisconfiguration


def extract_cors_misconfiguration(
    headers: dict[str, str], source_url: str
) -> CorsMisconfiguration | None:
    """Flag the one CORS misconfiguration that's unambiguous from response
    headers alone, with no probe `Origin` header needed: a wildcard
    `Access-Control-Allow-Origin: *` combined with
    `Access-Control-Allow-Credentials: true` is invalid per the Fetch spec
    (browsers themselves reject the combination) — a server sending both
    anyway is a real, well-documented misconfiguration, not a guess.

    Deliberately conservative: this does NOT try to detect origin
    reflection (echoing back whatever Origin was sent), since this tool
    never sends a probe Origin header of its own — that would need an
    active check, not passive header inspection of an already-made request.

    `headers` keys are expected lowercased (as `GuardedHttpClient` already
    normalizes them).
    """
    allow_origin = headers.get("access-control-allow-origin")
    if allow_origin is None:
        return None

    allow_credentials = headers.get("access-control-allow-credentials", "").strip().lower()
    if allow_origin.strip() == "*" and allow_credentials == "true":
        return CorsMisconfiguration(
            source_url=source_url, allow_origin=allow_origin, allow_credentials=True
        )
    return None
