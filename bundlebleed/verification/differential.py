from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

# Keyword substrings (case-insensitive) used only to flag which returned
# field NAMES look sensitive — never inspects values, never a claim about
# what the data actually is.
_SENSITIVE_FIELD_KEYWORDS = (
    "email",
    "phone",
    "ssn",
    "address",
    "token",
    "password",
    "name",
    "dob",
    "secret",
)


@dataclass(frozen=True)
class ResponseCapture:
    """A response a HUMAN captured themselves after running a drafted
    request. This tool never populates one from a live request."""

    status_code: int
    body: str


@dataclass
class DifferentialResult:
    status_match: bool
    body_length_delta: int
    json_keys_added: list[str] = field(default_factory=list)
    json_keys_removed: list[str] = field(default_factory=list)
    sensitive_fields_in_test: list[str] = field(default_factory=list)
    suggestion: str = ""


def _try_parse_json_object(body: str) -> dict[str, Any] | None:
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def compare_responses(baseline: ResponseCapture, test: ResponseCapture) -> DifferentialResult:
    """Pure comparison of two human-captured responses. Never fetches
    anything. `suggestion` is informational only — a human decides whether
    a hypothesis is confirmed, never this function.
    """
    status_match = baseline.status_code == test.status_code
    body_length_delta = len(test.body) - len(baseline.body)

    baseline_json = _try_parse_json_object(baseline.body)
    test_json = _try_parse_json_object(test.body)

    keys_added: list[str] = []
    keys_removed: list[str] = []
    sensitive_fields: list[str] = []

    if baseline_json is not None and test_json is not None:
        baseline_keys = set(baseline_json.keys())
        test_keys = set(test_json.keys())
        keys_added = sorted(test_keys - baseline_keys)
        keys_removed = sorted(baseline_keys - test_keys)
        sensitive_fields = sorted(
            k for k in test_keys if any(kw in k.lower() for kw in _SENSITIVE_FIELD_KEYWORDS)
        )

    if not status_match and test.status_code in (401, 403, 404):
        suggestion = "test request looks denied/not-found — likely properly protected"
    elif (
        status_match
        and baseline_json is not None
        and test_json is not None
        and not keys_added
        and not keys_removed
        and sensitive_fields
    ):
        suggestion = (
            "same response shape with sensitive-looking fields present — "
            "consistent with IDOR, needs human confirmation"
        )
    elif status_match:
        suggestion = "same status code — inspect bodies manually to judge"
    else:
        suggestion = "status codes differ — inspect manually"

    return DifferentialResult(
        status_match=status_match,
        body_length_delta=body_length_delta,
        json_keys_added=keys_added,
        json_keys_removed=keys_removed,
        sensitive_fields_in_test=sensitive_fields,
        suggestion=suggestion,
    )
