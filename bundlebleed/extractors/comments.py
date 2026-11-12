from __future__ import annotations

import re

from bundlebleed.models import FeatureFlag, InterestingComment

_SINGLE_LINE = re.compile(r"//(.+)")
_BLOCK_COMMENT = re.compile(r"/\*(.*?)\*/", re.DOTALL)

_COMMENT_KEYWORDS = frozenset(
    [
        "todo",
        "fixme",
        "hack",
        "xxx",
        "admin",
        "bypass",
        "auth",
        "password",
        "credential",
        "internal",
        "debug",
        "staging",
        "remove",
        "disable",
        "secret",
        "token",
        "hardcoded",
        "do not commit",
        "remove before",
        "test key",
        "private",
        "backdoor",
        "disabled check",
    ]
)

_FEATURE_FLAG_PATTERNS = [
    re.compile(r"\bfeatureFlags\b"),
    re.compile(r"\bfeatures\.isEnabled\s*\("),
    re.compile(r"\bFEATURE_[A-Z0-9_]+"),
    re.compile(r"\bwindow\.flags\b"),
    re.compile(r"\bconfig\.features\b"),
    re.compile(r"\bLaunchDarkly\b"),
    re.compile(r"\bOptimizely\b", re.IGNORECASE),
    re.compile(r"\bsplitio\b", re.IGNORECASE),
    re.compile(r"\bunleash\b", re.IGNORECASE),
    re.compile(r"\bflagsmith\b", re.IGNORECASE),
    re.compile(r"\bgrowthbook\b", re.IGNORECASE),
]

_FLAG_KEY_RE = re.compile(
    r"""(?:featureFlags|isEnabled|FEATURE_|flags)\s*[\[.('"]+\s*([A-Za-z0-9_.\-]+)"""
)
_FLAG_VALUE_RE = re.compile(r"""(?:true|false|['"]\w+['"]|\d+)""")

_ADMIN_FLAG_KEYWORDS = frozenset(["admin", "internal", "staff", "superuser", "debug", "backstage"])


def _line_number(content: str, pos: int) -> int:
    return content.count("\n", 0, pos) + 1


def extract_comments(
    content: str, source_url: str, file: str = ""
) -> tuple[list[InterestingComment], list[FeatureFlag]]:
    """Extract developer comments and feature flags from JS content.

    Both extractors run over the same content in one pass:
    - InterestingComment: single-line // and block /* */ comments that contain
      security-relevant keywords (credentials, bypass, internal URLs, etc.)
    - FeatureFlag: LaunchDarkly / Optimizely / custom isEnabled() patterns —
      flags with admin/internal keys feed the hypothesis engine as medium-confidence.
    """
    path = file or source_url
    comments: list[InterestingComment] = []
    flags: list[FeatureFlag] = []

    seen_comments: set[tuple[str, int]] = set()
    seen_flags: set[tuple[str, int]] = set()

    def _check_comment_text(text: str, line_no: int) -> None:
        lower = text.lower()
        for kw in sorted(_COMMENT_KEYWORDS):
            if kw in lower:
                # Dedup by (text, keyword) — same text with the same keyword
                # on different lines is merged; different keywords from the
                # same comment line each get their own entry.
                key = (text.strip()[:120], kw)
                if key not in seen_comments:
                    seen_comments.add(key)
                    comments.append(
                        InterestingComment(
                            text=text.strip()[:200],
                            file=path,
                            line=line_no,
                            keyword_matched=kw,
                            source_url=source_url,
                        )
                    )

    for m in _SINGLE_LINE.finditer(content):
        _check_comment_text(m.group(1), _line_number(content, m.start()))

    for m in _BLOCK_COMMENT.finditer(content):
        block = m.group(1)
        base_line = _line_number(content, m.start())
        for i, line in enumerate(block.splitlines()):
            _check_comment_text(line, base_line + i)

    for pat in _FEATURE_FLAG_PATTERNS:
        for m in pat.finditer(content):
            line_no = _line_number(content, m.start())
            snippet = content[m.start() : m.start() + 120]
            key_match = _FLAG_KEY_RE.search(snippet)
            key = key_match.group(1) if key_match else m.group(0)[:40]
            val_match = _FLAG_VALUE_RE.search(snippet[len(m.group(0)) :])
            value_hint = val_match.group(0) if val_match else ""

            dedup_key = (key, line_no)
            if dedup_key in seen_flags:
                continue
            seen_flags.add(dedup_key)

            flags.append(
                FeatureFlag(
                    key=key,
                    value_hint=value_hint,
                    file=path,
                    line=line_no,
                    source_url=source_url,
                )
            )

    return comments, flags
