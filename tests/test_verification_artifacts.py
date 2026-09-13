from __future__ import annotations

from bundlebleed.verification.artifacts import write_verification_artifacts
from bundlebleed.verification.models import RequestDraft, VerificationDraft


def _draft(cookie_placeholder: bool = True) -> VerificationDraft:
    headers = {"Cookie": "$BUNDLEBLEED_COOKIE"} if cookie_placeholder else {}
    return VerificationDraft(
        hypothesis_id="hyp-1",
        baseline=RequestDraft(
            url="https://example.com/api/v1/users/123",
            headers=dict(headers),
            comment="baseline (original id)",
        ),
        test=RequestDraft(
            url="https://example.com/api/v1/users/124",
            headers=dict(headers),
            comment="test (id + 1)",
        ),
        notes=["Use the 'admin' session's cookie for $BUNDLEBLEED_COOKIE."],
    )


def test_write_verification_artifacts_writes_three_files(tmp_path) -> None:  # type: ignore[no-untyped-def]
    paths = write_verification_artifacts(_draft(), tmp_path)

    assert len(paths) == 3
    names = {p.name for p in paths}
    assert names == {"request-baseline.http", "request-test.http", "curl-reproduce.sh"}
    assert all(p.exists() for p in paths)
    assert all(p.parent == tmp_path / "evidence" / "hyp-1" for p in paths)


def test_written_http_files_never_contain_a_real_cookie_value(tmp_path) -> None:  # type: ignore[no-untyped-def]
    paths = write_verification_artifacts(_draft(), tmp_path)
    for path in paths:
        content = path.read_text()
        assert "$BUNDLEBLEED_COOKIE" in content or "Cookie" not in content
        # never anything that looks like an actual session value
        assert "abc123" not in content


def test_http_file_content_has_method_and_url(tmp_path) -> None:  # type: ignore[no-untyped-def]
    write_verification_artifacts(_draft(), tmp_path)
    baseline = (tmp_path / "evidence" / "hyp-1" / "request-baseline.http").read_text()
    assert baseline.startswith("GET https://example.com/api/v1/users/123 HTTP/1.1")


def test_curl_script_mentions_both_requests_and_is_marked_as_not_executed(tmp_path) -> None:  # type: ignore[no-untyped-def]
    write_verification_artifacts(_draft(), tmp_path)
    script = (tmp_path / "evidence" / "hyp-1" / "curl-reproduce.sh").read_text()
    assert "nothing here has been run automatically" in script.lower()
    assert "users/123" in script
    assert "users/124" in script


def test_write_verification_artifacts_without_cookie_omits_cookie_header(tmp_path) -> None:  # type: ignore[no-untyped-def]
    write_verification_artifacts(_draft(cookie_placeholder=False), tmp_path)
    baseline = (tmp_path / "evidence" / "hyp-1" / "request-baseline.http").read_text()
    assert "Cookie" not in baseline
