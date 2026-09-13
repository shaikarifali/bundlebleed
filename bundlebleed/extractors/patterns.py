from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources

import yaml


@dataclass(frozen=True)
class CompiledEndpointPattern:
    name: str
    regex: re.Pattern[str]
    group: int


@dataclass(frozen=True)
class CompiledSecretPattern:
    name: str
    regex: re.Pattern[str]
    severity: str


@dataclass(frozen=True)
class SimplePattern:
    name: str
    regex: re.Pattern[str]


def _load_yaml(filename: str) -> dict[str, list[dict[str, str]]]:
    text = resources.files("bundlebleed.data").joinpath(filename).read_text()
    data = yaml.safe_load(text)
    if not isinstance(data, dict) or "patterns" not in data:
        raise ValueError(f"{filename}: expected a top-level 'patterns' list")
    return data


@lru_cache(maxsize=1)
def load_endpoint_patterns() -> list[CompiledEndpointPattern]:
    data = _load_yaml("endpoint_patterns.yaml")
    return [
        CompiledEndpointPattern(
            name=entry["name"], regex=re.compile(entry["regex"]), group=int(entry.get("group", 0))
        )
        for entry in data["patterns"]
    ]


def _load_simple_patterns(filename: str) -> list[SimplePattern]:
    data = _load_yaml(filename)
    return [
        SimplePattern(name=entry["name"], regex=re.compile(entry["regex"]))
        for entry in data["patterns"]
    ]


@lru_cache(maxsize=1)
def load_framework_patterns() -> list[SimplePattern]:
    return _load_simple_patterns("framework_signatures.yaml")


@lru_cache(maxsize=1)
def load_dom_sink_patterns() -> list[SimplePattern]:
    return _load_simple_patterns("dom_sinks.yaml")


@lru_cache(maxsize=1)
def load_dom_source_patterns() -> list[SimplePattern]:
    return _load_simple_patterns("dom_sources.yaml")


@lru_cache(maxsize=1)
def load_parameter_keywords() -> list[str]:
    text = resources.files("bundlebleed.data").joinpath("parameter_keywords.yaml").read_text()
    data = yaml.safe_load(text)
    if not isinstance(data, dict) or "keywords" not in data:
        raise ValueError("parameter_keywords.yaml: expected a top-level 'keywords' list")
    return [str(k).lower() for k in data["keywords"]]


@lru_cache(maxsize=1)
def load_secret_patterns() -> list[CompiledSecretPattern]:
    data = _load_yaml("secret_patterns.yaml")
    return [
        CompiledSecretPattern(
            name=entry["name"],
            regex=re.compile(entry["regex"]),
            severity=str(entry.get("severity", "medium")),
        )
        for entry in data["patterns"]
    ]
