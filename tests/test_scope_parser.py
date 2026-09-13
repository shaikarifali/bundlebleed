from __future__ import annotations

import pytest
from pydantic import ValidationError

from bundlebleed.scope.models import MatchType
from bundlebleed.scope.parser import (
    load_scope_config,
    parse_scope_txt,
    parse_scope_txt_file,
    parse_scope_yaml_file,
    parse_targets_arg,
)
from tests.conftest import FIXTURES_DIR


def test_parse_scope_txt_file_reads_entries_and_exclusions() -> None:
    config = parse_scope_txt_file(FIXTURES_DIR / "scope-samples" / "basic.txt")

    domains = {(e.domain, e.match_type) for e in config.in_scope}
    assert domains == {
        ("example.com", MatchType.EXACT),
        ("example.com", MatchType.WILDCARD),
        ("api.example.com", MatchType.EXACT),
    }
    assert config.out_of_scope == ["blog.example.com", "*.wordpress.example.com"]
    assert config.excluded_paths == []
    assert config.authorization_attested is False


def test_parse_scope_txt_skips_comments_and_blank_lines() -> None:
    config = parse_scope_txt("# comment\n\nexample.com\n")
    assert len(config.in_scope) == 1
    assert config.in_scope[0].domain == "example.com"


def test_parse_scope_yaml_file_reads_full_config() -> None:
    config = parse_scope_yaml_file(FIXTURES_DIR / "scope-samples" / "full.yaml")

    domains = {(e.domain, e.match_type) for e in config.in_scope}
    assert domains == {
        ("example.com", MatchType.WILDCARD),
        ("api.example.com", MatchType.EXACT),
    }
    assert config.out_of_scope == ["blog.example.com", "*.wordpress.example.com"]
    assert config.excluded_paths == ["/api/*/payment*", "*/checkout*"]
    assert config.authorization_attested is True
    assert config.scan.requests_per_second == 5
    assert config.scan.delay_between_domains == 2


def test_parse_scope_yaml_file_requires_scope_section(tmp_path) -> None:  # type: ignore[no-untyped-def]
    bad = tmp_path / "bad.yaml"
    bad.write_text("project:\n  name: x\n")
    with pytest.raises(ValueError, match="missing required 'scope' section"):
        parse_scope_yaml_file(bad)


def test_parse_scope_yaml_file_defaults_scan_settings_when_absent(tmp_path) -> None:  # type: ignore[no-untyped-def]
    minimal = tmp_path / "minimal.yaml"
    minimal.write_text("scope:\n  in_scope:\n    - domain: example.com\n      type: exact\n")
    config = parse_scope_yaml_file(minimal)
    assert config.scan.requests_per_second is None
    assert config.scan.delay_between_domains == 0.0


def test_parse_scope_yaml_file_fails_loudly_on_malformed_scan_section(tmp_path) -> None:  # type: ignore[no-untyped-def]
    bad = tmp_path / "bad_scan.yaml"
    bad.write_text(
        "scope:\n"
        "  in_scope:\n"
        "    - domain: example.com\n"
        "      type: exact\n"
        "scan:\n"
        "  requests_per_second: not-a-number\n"
    )
    with pytest.raises(ValidationError, match="requests_per_second"):
        parse_scope_yaml_file(bad)


def test_parse_targets_arg_handles_wildcard_and_exact() -> None:
    config = parse_targets_arg("example.com, *.api.example.com")
    assert config.in_scope[0].domain == "example.com"
    assert config.in_scope[0].match_type == MatchType.EXACT
    assert config.in_scope[1].domain == "api.example.com"
    assert config.in_scope[1].match_type == MatchType.WILDCARD


def test_load_scope_config_requires_exactly_one_source() -> None:
    with pytest.raises(ValueError, match="one of -t, -tL, or --config is required"):
        load_scope_config(None, None, None)

    with pytest.raises(ValueError, match="only one of"):
        load_scope_config("example.com", FIXTURES_DIR / "scope-samples" / "basic.txt", None)


def test_load_scope_config_dispatches_to_target_arg() -> None:
    config = load_scope_config("example.com", None, None)
    assert config.in_scope[0].domain == "example.com"
