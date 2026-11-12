from __future__ import annotations

import json

from bundlebleed.verification.differential import ResponseCapture, compare_responses


def test_access_denied_when_test_status_is_403() -> None:
    baseline = ResponseCapture(status_code=200, body='{"id": 1, "name": "me"}')
    test = ResponseCapture(status_code=403, body="Forbidden")

    result = compare_responses(baseline, test)

    assert result.status_match is False
    assert "denied" in result.suggestion.lower() or "protected" in result.suggestion.lower()


def test_same_shape_different_data_flags_sensitive_fields() -> None:
    baseline = ResponseCapture(
        status_code=200, body=json.dumps({"id": 1, "email": "me@example.com"})
    )
    test = ResponseCapture(status_code=200, body=json.dumps({"id": 2, "email": "victim@x.com"}))

    result = compare_responses(baseline, test)

    assert result.status_match is True
    assert result.json_keys_added == []
    assert result.json_keys_removed == []
    assert "email" in result.sensitive_fields_in_test
    assert "idor" in result.suggestion.lower()


def test_structurally_different_json_reports_key_diff() -> None:
    baseline = ResponseCapture(status_code=200, body=json.dumps({"id": 1}))
    test = ResponseCapture(status_code=200, body=json.dumps({"error": "not found"}))

    result = compare_responses(baseline, test)

    assert result.json_keys_added == ["error"]
    assert result.json_keys_removed == ["id"]


def test_non_json_bodies_do_not_crash_and_report_no_key_diff() -> None:
    baseline = ResponseCapture(status_code=200, body="<html>hi</html>")
    test = ResponseCapture(status_code=200, body="<html>bye</html>")

    result = compare_responses(baseline, test)

    assert result.json_keys_added == []
    assert result.json_keys_removed == []
    assert result.body_length_delta == len("<html>bye</html>") - len("<html>hi</html>")


def test_body_length_delta_sign() -> None:
    baseline = ResponseCapture(status_code=200, body="short")
    test = ResponseCapture(status_code=200, body="a much longer body here")

    result = compare_responses(baseline, test)

    assert result.body_length_delta == len("a much longer body here") - len("short")


def test_never_treats_suggestion_as_authoritative_naming() -> None:
    """The suggestion text must never claim a confirmed/rejected verdict —
    that phrasing is reserved for a human's explicit `verify record` call."""
    baseline = ResponseCapture(status_code=200, body='{"id": 1}')
    test = ResponseCapture(status_code=200, body='{"id": 2, "email": "x@example.com"}')
    result = compare_responses(baseline, test)
    assert "confirmed" not in result.suggestion.lower()
    assert "rejected" not in result.suggestion.lower()
