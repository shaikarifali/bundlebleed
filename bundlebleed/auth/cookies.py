from __future__ import annotations

import json
from pathlib import Path


def _from_json(text: str) -> str | None:
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(data, list):
        return None
    pairs = []
    for entry in data:
        if not isinstance(entry, dict) or "name" not in entry or "value" not in entry:
            return None
        pairs.append(f"{entry['name']}={entry['value']}")
    return "; ".join(pairs)


def _from_netscape(text: str) -> str | None:
    pairs = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split("\t")
        if len(fields) != 7:
            return None
        name, value = fields[5], fields[6]
        pairs.append(f"{name}={value}")
    return "; ".join(pairs) if pairs else None


def parse_cookie_text(text: str) -> str:
    """Parse a cookie file's content into a normalized `Cookie:` header
    value. Auto-detects JSON (`[{"name": ..., "value": ...}, ...]`) and
    Netscape cookies.txt (tab-separated) formats, falling back to treating
    the content as an already-formed raw header string (`k=v; k2=v2`).
    """
    text = text.strip()
    if not text:
        raise ValueError("empty cookie content")

    if text.startswith("["):
        parsed = _from_json(text)
        if parsed is not None:
            return parsed
        raise ValueError("looked like JSON but did not match [{'name','value'}, ...]")

    if "\t" in text:
        parsed = _from_netscape(text)
        if parsed is not None:
            return parsed

    return text


def parse_cookie_file(path: Path) -> str:
    return parse_cookie_text(path.read_text())
