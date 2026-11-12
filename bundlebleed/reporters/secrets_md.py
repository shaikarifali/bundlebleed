from __future__ import annotations

from pathlib import Path

from bundlebleed.models import ScanResult

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

_WARNING = """\
> **Handle with care.**
> Values are **redacted** (type + preview + partial SHA256 only — never plaintext).
> Never commit this file to version control. Never share in unencrypted channels.
> Every entry is a *manual verification lead*, not a confirmed secret.
"""


def render_secrets_md(result: ScanResult) -> str:
    """Render a standalone secrets report with two sections.

    §5.1: Pattern-matched secrets (regex-identified — AWS keys, GH tokens, etc.)
    §5.2: Entropy-discovered secrets (high Shannon-entropy tokens — manual review needed)

    Secret values are **never stored in plaintext** anywhere in BundleBleed.
    What is stored: type + redacted preview (first 4 chars + '...') + partial SHA256.
    That is enough to identify the secret on re-encounter but not to replay it.
    """
    r = result.normalized()
    lines: list[str] = [
        "# Secrets Report",
        "",
        _WARNING,
        "",
        f"Generated: `{r.started_at.isoformat()}`  ",
        f"Scan run ID: `{r.scan_run_id}`  ",
        f"Targets: {', '.join(r.targets) or '(none)'}",
        "",
    ]

    # -------------------------------------------------------------------
    # §5.1 — Pattern-matched secrets
    # -------------------------------------------------------------------
    lines += ["## 5.1 Pattern-matched secrets", ""]
    if not r.secrets:
        lines.append("_None found._")
    else:
        lines.append(f"**{len(r.secrets)} finding(s)**")
        lines.append("")
        lines.append("| Type | Severity | Redacted value | Partial SHA256 | Source |")
        lines.append("|---|---|---|---|---|")
        for s in sorted(r.secrets, key=lambda s: (_SEV_ORDER.get(s.severity, 99), s.secret_type)):
            lines.append(
                f"| `{s.secret_type}` | **{s.severity}** | `{s.redacted_value}` "
                f"| `{s.partial_hash}` | {s.source_url} |"
            )

    lines += ["", "---", ""]

    # -------------------------------------------------------------------
    # §5.2 — Entropy-discovered secrets
    # -------------------------------------------------------------------
    lines += ["## 5.2 High-entropy tokens (manual review required)", ""]
    lines.append(
        "These tokens had Shannon entropy ≥ 4.0 bits over tokens of ≥ 20 characters "
        "but did not match a known secret pattern. Each needs manual review to determine "
        "if it is an API key, internal token, or benign high-entropy string (e.g. a minified "
        "variable name or a UUID)."
    )
    lines.append("")
    if not r.entropy_secrets:
        lines.append("_None found._")
    else:
        lines.append(f"**{len(r.entropy_secrets)} candidate(s)**")
        lines.append("")
        lines.append("| Entropy | Redacted value | Partial SHA256 | Line | Source |")
        lines.append("|---|---|---|---|---|")
        for e in sorted(r.entropy_secrets, key=lambda e: -e.entropy_score):
            lines.append(
                f"| {e.entropy_score:.2f} | `{e.redacted_value}` | `{e.partial_hash}` "
                f"| {e.line} | {e.source_url} |"
            )

    lines.append("")
    return "\n".join(lines)


def write_secrets_md(result: ScanResult, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "secrets.md"
    path.write_text(render_secrets_md(result))
    return path
