from __future__ import annotations

import pytest

from bundlebleed.ai.prompt_loader import (
    _VERSION_PREFIX,
    _parse,
    load_attack_chain_prompt,
    load_attack_chain_system_prompt,
    load_endpoint_analysis_prompt,
    load_report_writer_prompt,
    load_report_writer_system_prompt,
    load_system_prompt,
)


def test_load_system_prompt_has_a_version() -> None:
    prompt = load_system_prompt()
    assert prompt.version == "endpoint-intel-v1"
    assert "BUNDLEBLEED-PROMPT-VERSION" not in prompt.text
    assert "evidence" in prompt.text.lower()


def test_load_endpoint_analysis_prompt_has_a_placeholder() -> None:
    prompt = load_endpoint_analysis_prompt()
    assert prompt.version == "endpoint-intel-v1"
    assert "{evidence_bundle}" in prompt.text


def test_load_report_writer_system_prompt_has_a_version() -> None:
    prompt = load_report_writer_system_prompt()
    assert prompt.version == "report-writer-v1"
    assert "draft" in prompt.text.lower()


def test_load_report_writer_prompt_has_a_placeholder() -> None:
    prompt = load_report_writer_prompt()
    assert prompt.version == "report-writer-v1"
    assert "{evidence}" in prompt.text


def test_load_attack_chain_system_prompt_has_a_version() -> None:
    prompt = load_attack_chain_system_prompt()
    assert prompt.version == "attack-chain-v1"
    assert "hypothesis_ids" in prompt.text


def test_load_attack_chain_prompt_has_a_placeholder() -> None:
    prompt = load_attack_chain_prompt()
    assert prompt.version == "attack-chain-v1"
    assert "{evidence}" in prompt.text


def test_parse_extracts_version_and_strips_header_line() -> None:
    raw = f"{_VERSION_PREFIX} my-version-1\nsome prompt text\nmore text\n"
    prompt = _parse(raw, "fake.txt")
    assert prompt.version == "my-version-1"
    assert prompt.text == "some prompt text\nmore text\n"


def test_parse_fails_loudly_on_missing_header() -> None:
    with pytest.raises(ValueError, match="missing"):
        _parse("just some text with no header\n", "bad.txt")


def test_parse_fails_loudly_on_empty_version() -> None:
    with pytest.raises(ValueError, match="empty version"):
        _parse(f"{_VERSION_PREFIX}   \nbody\n", "bad.txt")
