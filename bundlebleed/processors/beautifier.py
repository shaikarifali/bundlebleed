from __future__ import annotations

import jsbeautifier


def beautify(content: str) -> str:
    """De-minify JS before regex extraction, for better match quality.

    `content` is attacker-controlled (fetched from a third-party target), so
    a malformed/pathological bundle must degrade to the raw content rather
    than aborting the whole scan.
    """
    try:
        return str(jsbeautifier.beautify(content))
    except Exception:
        return content
