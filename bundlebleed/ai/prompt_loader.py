from __future__ import annotations

from dataclasses import dataclass
from importlib import resources

_VERSION_PREFIX = "BUNDLEBLEED-PROMPT-VERSION:"


@dataclass(frozen=True)
class Prompt:
    version: str
    text: str


def _parse(raw: str, filename: str) -> Prompt:
    first_line, _, rest = raw.partition("\n")
    if not first_line.startswith(_VERSION_PREFIX):
        raise ValueError(f"{filename}: missing '{_VERSION_PREFIX}' header on line 1")
    version = first_line[len(_VERSION_PREFIX) :].strip()
    if not version:
        raise ValueError(f"{filename}: '{_VERSION_PREFIX}' header has an empty version")
    return Prompt(version=version, text=rest)


def _load(filename: str) -> Prompt:
    raw = resources.files("bundlebleed.ai.prompts").joinpath(filename).read_text()
    return _parse(raw, filename)


def load_system_prompt() -> Prompt:
    return _load("system_prompt.txt")


def load_endpoint_analysis_prompt() -> Prompt:
    return _load("endpoint_analysis.txt")


def load_report_writer_system_prompt() -> Prompt:
    return _load("report_writer_system.txt")


def load_report_writer_prompt() -> Prompt:
    return _load("report_writer.txt")


def load_attack_chain_system_prompt() -> Prompt:
    return _load("attack_chain_system.txt")


def load_attack_chain_prompt() -> Prompt:
    return _load("attack_chain.txt")
