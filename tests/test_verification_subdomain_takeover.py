from __future__ import annotations

from unittest.mock import patch

import dns.resolver

from bundlebleed.verification.subdomain_takeover import (
    check_dangling_cname,
    check_dangling_cnames,
    resolve_cname,
)


class _FakeTarget:
    def __init__(self, name: str) -> None:
        self._name = name

    def __str__(self) -> str:
        return self._name


class _FakeRecord:
    def __init__(self, target: str) -> None:
        self.target = _FakeTarget(target)


class _FakeAnswer:
    def __init__(self, rrset: list[_FakeRecord] | None) -> None:
        self.rrset = rrset


def test_resolve_cname_returns_target_on_success() -> None:
    fake = _FakeAnswer([_FakeRecord("some-app.herokuapp.com.")])
    with patch("dns.resolver.resolve", return_value=fake):
        assert resolve_cname("blog.example.com") == "some-app.herokuapp.com"


def test_resolve_cname_returns_none_on_nxdomain() -> None:
    with patch("dns.resolver.resolve", side_effect=dns.resolver.NXDOMAIN()):  # type: ignore[no-untyped-call]
        assert resolve_cname("nonexistent.example.com") is None


def test_resolve_cname_returns_none_when_no_cname_record() -> None:
    with patch("dns.resolver.resolve", return_value=_FakeAnswer(None)):
        assert resolve_cname("api.example.com") is None


def test_resolve_cname_returns_none_on_empty_rrset() -> None:
    with patch("dns.resolver.resolve", return_value=_FakeAnswer([])):
        assert resolve_cname("api.example.com") is None


def test_dangling_cname_flagged_for_known_takeover_prone_service() -> None:
    fake = _FakeAnswer([_FakeRecord("some-unclaimed-app.herokuapp.com.")])
    with patch("dns.resolver.resolve", return_value=fake):
        finding = check_dangling_cname("blog.example.com")
    assert finding is not None
    assert finding.domain == "blog.example.com"
    assert finding.cname_target == "some-unclaimed-app.herokuapp.com"
    assert finding.service_hint == "herokuapp.com"


def test_cname_to_ordinary_first_party_host_is_not_flagged() -> None:
    fake = _FakeAnswer([_FakeRecord("internal-lb.example.com.")])
    with patch("dns.resolver.resolve", return_value=fake):
        finding = check_dangling_cname("api.example.com")
    assert finding is None


def test_no_cname_record_is_not_flagged() -> None:
    with patch("dns.resolver.resolve", return_value=_FakeAnswer(None)):
        finding = check_dangling_cname("api.example.com")
    assert finding is None


def test_check_dangling_cnames_checks_every_domain_and_skips_non_matches() -> None:
    def fake_resolve(domain: str, *_args: object, **_kwargs: object) -> _FakeAnswer:
        if domain == "assets.example.com":
            return _FakeAnswer([_FakeRecord("old-bucket.s3.amazonaws.com.")])
        return _FakeAnswer([_FakeRecord("internal.example.com.")])

    with patch("dns.resolver.resolve", side_effect=fake_resolve):
        findings = check_dangling_cnames(["api.example.com", "assets.example.com"])

    assert len(findings) == 1
    assert findings[0].domain == "assets.example.com"
    assert findings[0].service_hint == "s3.amazonaws.com"
