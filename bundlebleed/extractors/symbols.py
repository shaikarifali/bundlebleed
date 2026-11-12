from __future__ import annotations

import re

from bundlebleed.models import Symbol

_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("global", re.compile(r"\bwindow\.([A-Za-z_$][A-Za-z0-9_$]*)\s*=")),
    ("global", re.compile(r"\bglobalThis\.([A-Za-z_$][A-Za-z0-9_$]*)\s*=")),
    ("export", re.compile(r"\bexport\s+(?:default\s+)?(?:function|class|const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)")),
    ("export", re.compile(r"\bexport\s*\{([^}]+)\}")),
    ("module", re.compile(r"\bmodule\.exports\s*=\s*([A-Za-z_$][A-Za-z0-9_$]*)")),
    ("function", re.compile(r"^(?:async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(", re.MULTILINE)),
    ("const", re.compile(r"^const\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=", re.MULTILINE)),
    ("let", re.compile(r"^let\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=", re.MULTILINE)),
    ("var", re.compile(r"^var\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=", re.MULTILINE)),
]

_EXPORT_NAMES_RE = re.compile(r"([A-Za-z_$][A-Za-z0-9_$]*)")


def _line_number(content: str, pos: int) -> int:
    return content.count("\n", 0, pos) + 1


def extract_symbols(content: str, source_url: str, file: str = "") -> list[Symbol]:
    """Extract top-level JS symbols: globals, exports, and module bindings.

    Written to `ast/symbols.json` and used by the parameter→function mapper
    and the AI analysis layer. Duplicate name+line combos are deduplicated.
    """
    path = file or source_url
    seen: set[tuple[str, int]] = set()
    results: list[Symbol] = []

    for kind, pat in _PATTERNS:
        for m in pat.finditer(content):
            line_no = _line_number(content, m.start())

            if kind == "export" and "{" in m.group(0):
                for nm in _EXPORT_NAMES_RE.finditer(m.group(1)):
                    name = nm.group(1)
                    # Dedup by name only — multiple declarations of the same
                    # symbol (re-exports, minified duplicates) are merged.
                    if name not in seen:
                        seen.add(name)
                        results.append(Symbol(name=name, kind="export", file=path, line=line_no))
            else:
                name = m.group(1)
                if name not in seen:
                    seen.add(name)
                    results.append(Symbol(name=name, kind=kind, file=path, line=line_no))  # type: ignore[arg-type]

    return results
