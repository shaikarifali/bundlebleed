from __future__ import annotations

import re

from pydantic import BaseModel, Field


class ProtoPollutionFinding(BaseModel):
    """Prototype pollution signal extracted from JS source.

    Levels:
      1 = direct __proto__ property write
      2 = constructor.prototype chain manipulation
      3 = unsafe deep-merge/extend function (lodash/jQuery/custom)
      4 = dynamic bracket-notation write (obj[key]=val, key may be __proto__)
      5 = Object.prototype direct mutation
    """

    level: int
    pattern_name: str
    detail: str
    gadgets: list[str] = Field(default_factory=list)  # security-sensitive downstream uses
    file: str
    line: int
    source_url: str


# ---------------------------------------------------------------------------
# Detection patterns by level
# ---------------------------------------------------------------------------

# L1 — direct __proto__ property access / write
_L1_PATTERNS = [
    (re.compile(r"""__proto__\s*\["""), "proto_bracket_write"),
    (re.compile(r"""__proto__\s*\.\s*\w+\s*=(?!=)"""), "proto_dot_write"),
    (re.compile(r"""__proto__\s*=\s*\{"""), "proto_object_assign"),
]

# L2 — constructor.prototype chain
_L2_PATTERNS = [
    (re.compile(r"""\.constructor\.prototype\s*\.\s*\w+\s*=(?!=)"""), "ctor_prototype_write"),
    (re.compile(r"""\.constructor\.prototype\s*\["""), "ctor_prototype_bracket"),
]

# L3 — unsafe deep-merge / extend functions known to be pollutable
_L3_PATTERNS = [
    (re.compile(r"""\b_\.merge\s*\("""), "lodash_merge"),
    (re.compile(r"""\b_\.defaultsDeep\s*\("""), "lodash_defaultsDeep"),
    (re.compile(r"""\bjQuery\.extend\s*\(\s*true"""), "jquery_extend_deep"),
    (re.compile(r"""\$\.extend\s*\(\s*true"""), "jquery_extend_deep_$"),
    (re.compile(r"""\bdeepMerge\s*\("""), "custom_deepMerge"),
    (re.compile(r"""\bmergeDeep\s*\("""), "custom_mergeDeep"),
    (re.compile(r"""\bdeepExtend\s*\("""), "custom_deepExtend"),
    (re.compile(r"""\brecursiveMerge\s*\("""), "custom_recursiveMerge"),
    (re.compile(r"""\bObject\.assign\s*\(\s*(?:\w+|this)\s*,\s*(?:req\.|body|params|query|data)"""), "Object.assign_untrusted"),
]

# L4 — dynamic bracket-notation write (key could be __proto__)
_L4_PATTERNS = [
    (re.compile(r"""(?:obj|target|result|dest|base|config|options|settings)\s*\[\s*(?:key|prop|name|attr|k)\s*\]\s*=(?!=)"""), "dynamic_key_write"),
    (re.compile(r"""(?:for\s*\([^)]+\s+in\s+[^)]+\))\s*\{[^}]*\[\s*\w+\s*\]\s*=(?!=)"""), "for_in_copy"),
]

# L5 — Object.prototype direct mutation
_L5_PATTERNS = [
    (re.compile(r"""Object\.prototype\s*\.\s*[a-zA-Z_$][\w$]*\s*=(?!=)"""), "Object.prototype_write"),
    (re.compile(r"""Object\.prototype\s*\[['"]\w+['"]\]\s*=(?!=)"""), "Object.prototype_bracket_write"),
]

_ALL_LEVELS: list[tuple[list[tuple[re.Pattern, str]], int]] = [
    (_L1_PATTERNS, 1),
    (_L2_PATTERNS, 2),
    (_L3_PATTERNS, 3),
    (_L4_PATTERNS, 4),
    (_L5_PATTERNS, 5),
]

# Gadget patterns — downstream uses that make pollution exploitable
_GADGET_PATTERNS: dict[str, re.Pattern] = {
    "innerHTML_gadget": re.compile(r"""\.innerHTML\s*=(?!=)"""),
    "eval_gadget": re.compile(r"""\beval\s*\("""),
    "template_gadget": re.compile(r"""(?:template|tmpl|render)\s*\("""),
    "isAdmin_gadget": re.compile(r"""\bisAdmin\b"""),
    "role_gadget": re.compile(r"""\brole\b"""),
    "permissions_gadget": re.compile(r"""\bpermissions\b"""),
    "Function_gadget": re.compile(r"""\bnew\s+Function\s*\("""),
}


def _line_number(content: str, pos: int) -> int:
    return content.count("\n", 0, pos) + 1


def _find_gadgets(content: str) -> list[str]:
    return [name for name, pat in _GADGET_PATTERNS.items() if pat.search(content)]


def extract_proto_pollution(
    content: str, source_url: str, file: str = ""
) -> list[ProtoPollutionFinding]:
    """Find prototype pollution patterns in JS content.

    Returns one finding per unique (pattern_name, line) pair, sorted by level
    descending so the highest-impact findings appear first.  Gadgets are
    computed file-wide (a pollution write anywhere in the file + a gadget
    anywhere in the file = elevated risk), not line-locally, since gadget
    execution paths are hard to trace statically.
    """
    path = file or source_url
    findings: list[ProtoPollutionFinding] = []
    seen: set[tuple[str, int]] = set()

    # Compute gadgets once for the whole file
    gadgets = _find_gadgets(content)

    for patterns, level in _ALL_LEVELS:
        for pat, pat_name in patterns:
            for m in pat.finditer(content):
                line_no = _line_number(content, m.start())
                key = (pat_name, line_no)
                if key in seen:
                    continue
                seen.add(key)
                snippet = m.group(0)[:100]
                findings.append(
                    ProtoPollutionFinding(
                        level=level,
                        pattern_name=pat_name,
                        detail=f"[L{level}] {pat_name}: `{snippet}`",
                        gadgets=gadgets,
                        file=path,
                        line=line_no,
                        source_url=source_url,
                    )
                )

    return sorted(findings, key=lambda f: (-f.level, f.line))


def proto_pollution_risk_flags(findings: list[ProtoPollutionFinding]) -> list[str]:
    """Human-readable risk summaries for prototype pollution findings."""
    flags: list[str] = []
    if not findings:
        return flags
    max_level = max(f.level for f in findings)
    l5 = [f for f in findings if f.level == 5]
    l4 = [f for f in findings if f.level == 4]
    l3 = [f for f in findings if f.level == 3]
    all_gadgets = {g for f in findings for g in f.gadgets}
    if l5:
        flags.append(f"Object.prototype direct mutation ({len(l5)} sites) — high-confidence prototype pollution write")
    if l3:
        funcs = {f.pattern_name for f in l3}
        flags.append(f"Unsafe deep-merge functions detected: {', '.join(sorted(funcs))} — pollutable with crafted object input")
    if l4:
        flags.append(f"Dynamic bracket-notation writes ({len(l4)} sites) — key may be __proto__ if derived from user input")
    if max_level >= 3 and all_gadgets:
        flags.append(f"Pollution gadgets present: {', '.join(sorted(all_gadgets))} — pollution may reach security-sensitive sinks")
    return flags
