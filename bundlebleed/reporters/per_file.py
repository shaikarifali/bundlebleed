from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

from bundlebleed.models import ScanResult

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _interest_score(
    n_secrets: int,
    n_entropy: int,
    n_bola: int,
    n_auth: int,
    n_dom: int,
    n_proto: int,
    n_graphql: int,
    n_params: int,
) -> int:
    """Rough interest score used to sort per-file reports by recon value."""
    return (
        n_secrets * 10
        + n_entropy * 3
        + n_bola * 8
        + n_auth * 5
        + n_dom * 6
        + n_proto * 7
        + n_graphql * 4
        + n_params * 1
    )


def render_per_file(file_url: str, result: ScanResult) -> str:
    """Render a focused analysis report for a single JS file.

    Surfaces all findings whose `source_url` matches `file_url`, organised by
    section.  Every section shows only findings for this file — not the whole
    scan — so the report is fast to scan during triage.
    """
    r = result.normalized()
    url = file_url

    # Collect per-file slices
    secrets = [s for s in r.secrets if s.source_url == url]
    entropy = [e for e in r.entropy_secrets if e.source_url == url]
    endpoints = [e for e in r.endpoints if e.source_url == url]
    params = [p for p in r.parameters if p.source_url == url]
    comments = [c for c in r.interesting_comments if c.source_url == url]
    flags = [f for f in r.feature_flags if f.source_url == url]
    symbols = [s for s in r.symbols if s.source_url == url]
    graphql = [op for op in r.graphql_operations if op.source_url == url]
    ws = [ws for ws in r.websocket_findings if ws.source_url == url]
    auth = [af for af in r.auth_findings if af.source_url == url]
    bola = [oc for oc in r.object_access_candidates if oc.source_url == url]
    dom = [d for d in r.dom_taint_findings if d.source_url == url]
    proto = [p for p in r.proto_pollution_findings if p.source_url == url]
    pm = [pm for pm in r.postmessage_findings if pm.source_url == url]
    workers = [w for w in r.worker_findings if w.source_url == url]

    score = _interest_score(
        len(secrets), len(entropy), len(bola), len(auth),
        len(dom), len(proto), len(graphql), len(params),
    )

    parsed = urlparse(url)
    short_name = parsed.path.split("/")[-1] or parsed.netloc

    lines: list[str] = [
        f"# {short_name}",
        "",
        f"**URL:** `{url}`  ",
        f"**Interest score:** {score}  ",
        f"**Findings:** {len(secrets)+len(entropy)} secrets, "
        f"{len(bola)} BOLA, {len(auth)} auth signals, "
        f"{len(dom)} DOM taint, {len(endpoints)} endpoints",
        "",
    ]

    # Linked file analysis
    matched_files = [f for f in r.files if f.url == url]
    if matched_files:
        fa = matched_files[0]
        if fa.frameworks:
            lines.append(f"**Frameworks:** {', '.join(fa.frameworks)}")
        if fa.source_map_found:
            lines.append(f"**Source map:** `{fa.source_map_url}`")
        lines.append("")

    # ── Secrets ────────────────────────────────────────────────────────
    if secrets:
        lines += ["## Secrets (pattern-matched)", ""]
        lines.append("| Type | Severity | Redacted | Partial hash |")
        lines.append("|---|---|---|---|")
        for s in sorted(secrets, key=lambda s: _SEV_ORDER.get(s.severity, 99)):
            lines.append(f"| `{s.secret_type}` | **{s.severity}** | `{s.redacted_value}` | `{s.partial_hash}` |")
        lines.append("")

    if entropy:
        lines += ["## Entropy secrets", ""]
        lines.append("| Entropy | Redacted | Line |")
        lines.append("|---|---|---|")
        for e in sorted(entropy, key=lambda e: -e.entropy_score):
            lines.append(f"| {e.entropy_score:.2f} | `{e.redacted_value}` | {e.line} |")
        lines.append("")

    # ── Access control ─────────────────────────────────────────────────
    if bola:
        lines += ["## Access control candidates", ""]
        lines.append("| Bug class | Level | Endpoint | Identifier | Function |")
        lines.append("|---|---|---|---|---|")
        for c in sorted(bola, key=lambda c: (-c.level, c.endpoint)):
            fn = c.function_name or "-"
            lines.append(f"| **{c.bug_class}** | {c.level} | `{c.endpoint}` | `{c.identifier}` | `{fn}` |")
        lines.append("")

    # ── Auth configuration ─────────────────────────────────────────────
    if auth:
        lines += ["## Auth configuration signals", ""]
        lines.append("| Type | Severity | Detail | Line |")
        lines.append("|---|---|---|---|")
        for af in sorted(auth, key=lambda af: _SEV_ORDER.get(af.severity_candidate, 99)):
            lines.append(f"| `{af.finding_type}` | {af.severity_candidate} | {af.detail[:80]} | {af.line} |")
        lines.append("")

    # ── DOM taint ──────────────────────────────────────────────────────
    if dom:
        lines += ["## DOM taint findings", ""]
        lines.append("| Source | Line | Sink | Line | Category |")
        lines.append("|---|---|---|---|---|")
        for d in dom:
            lines.append(f"| `{d.source_name}` | {d.source_line} | `{d.sink_name}` | {d.sink_line} | {d.sink_category} |")
        lines.append("")

    # ── Prototype pollution ────────────────────────────────────────────
    if proto:
        lines += ["## Prototype pollution findings", ""]
        lines.append("| Level | Pattern | Line | Gadgets |")
        lines.append("|---|---|---|---|")
        for p in sorted(proto, key=lambda p: (-p.level, p.line)):
            gadgets = ", ".join(p.gadgets[:3]) if hasattr(p, "gadgets") else "-"
            lines.append(f"| L{p.level} | `{p.pattern_name}` | {p.line} | {gadgets} |")
        lines.append("")

    # ── GraphQL ────────────────────────────────────────────────────────
    if graphql:
        lines += ["## GraphQL operations", ""]
        lines.append("| Type | Name | Variables | Endpoint |")
        lines.append("|---|---|---|---|")
        for op in graphql:
            vars_str = ", ".join(f"`{v}`" for v in op.variables[:5])
            lines.append(f"| {op.op_type} | `{op.op_name}` | {vars_str or '-'} | `{op.endpoint}` |")
        lines.append("")

    # ── WebSocket ──────────────────────────────────────────────────────
    if ws:
        lines += ["## WebSocket findings", ""]
        for w in ws:
            risk = []
            if w.auth_in_url:
                risk.append("⚠️ auth-in-URL")
            if not w.has_origin_check:
                risk.append("no origin check")
            risk_str = ", ".join(risk) or "—"
            lines.append(f"- `{w.endpoint}` ({w.protocol}) — {risk_str}")
        lines.append("")

    # ── postMessage ────────────────────────────────────────────────────
    if pm:
        lines += ["## postMessage findings", ""]
        for m in pm:
            if m.kind == "sender":
                origin_note = f"targetOrigin=`{m.target_origin}`"
                if m.target_origin == "*":
                    origin_note += " ⚠️ wildcard"
                lines.append(f"- **Sender** {origin_note} (line {m.line})")
            else:
                origin_note = "origin check: ✓" if m.has_origin_check else "origin check: ✗ ⚠️"
                sinks = ", ".join(m.data_sinks) if m.data_sinks else "none"
                lines.append(f"- **Receiver** {origin_note}, sinks: {sinks} (line {m.line})")
        lines.append("")

    # ── Workers ────────────────────────────────────────────────────────
    if workers:
        lines += ["## Worker findings", ""]
        for w in workers:
            blob_note = " (blob URL — not statically inspectable)" if w.is_inline_blob else ""
            fetch_note = " intercepts fetch" if w.has_fetch_intercept else ""
            lines.append(f"- {w.worker_type}: `{w.worker_url or '(dynamic)'}`{blob_note}{fetch_note}")
        lines.append("")

    # ── Endpoints ──────────────────────────────────────────────────────
    if endpoints:
        lines += ["## Endpoints", ""]
        lines.append("| Value | Pattern | Tag |")
        lines.append("|---|---|---|")
        for e in endpoints:
            lines.append(f"| `{e.value}` | {e.pattern_name} | {e.tag} |")
        lines.append("")

    # ── Parameters ─────────────────────────────────────────────────────
    if params:
        lines += ["## Parameters", ""]
        for p in params:
            fn_note = f" (in `{p.function_name}()`)" if p.function_name else ""
            lines.append(f"- `{p.name}`{fn_note}")
        lines.append("")

    # ── Comments ───────────────────────────────────────────────────────
    if comments:
        lines += ["## Interesting comments", ""]
        for c in comments[:20]:
            lines.append(f"- **[{c.keyword_matched}]** line {c.line}: `{c.text[:100]}`")
        lines.append("")

    # ── Feature flags ──────────────────────────────────────────────────
    if flags:
        lines += ["## Feature flags", ""]
        for f in flags[:20]:
            lines.append(f"- `{f.key}` (hint: `{f.value_hint}`) line {f.line}")
        lines.append("")

    # ── Symbols ────────────────────────────────────────────────────────
    if symbols:
        lines += ["## Exported symbols", ""]
        exp = [s for s in symbols if s.kind in ("export", "global", "module")][:20]
        for s in exp:
            lines.append(f"- `{s.name}` ({s.kind}) line {s.line}")
        if len(symbols) > 20:
            lines.append(f"_... {len(symbols) - 20} more_")
        lines.append("")

    if score == 0:
        lines.append("_No notable findings for this file._")

    return "\n".join(lines)


def _file_slug(url: str) -> str:
    """Safe filename from a URL."""
    parsed = urlparse(url)
    name = parsed.path.replace("/", "_").strip("_") or parsed.netloc
    return name[:120]


def write_per_file_analyses(
    result: ScanResult,
    output_dir: Path,
    min_score: int = 0,
) -> list[Path]:
    """Write one .md file per JS file, to <output_dir>/analysis/.

    Files with interest score < min_score are skipped (default: write all).
    Returns the list of paths written, sorted by score descending.
    """
    r = result.normalized()
    all_urls = list(dict.fromkeys(
        [f.url for f in r.files]
        + [e.source_url for e in r.endpoints]
        + [s.source_url for s in r.secrets]
    ))

    out = output_dir / "analysis"
    out.mkdir(parents=True, exist_ok=True)

    written: list[tuple[int, Path]] = []
    seen_slugs: set[str] = set()

    for url in all_urls:
        content = render_per_file(url, result)
        # Quick score extraction from first line
        score_line = next((l for l in content.splitlines() if "Interest score" in l), "")
        try:
            score = int(score_line.split("**Interest score:**")[1].split("  ")[0].strip())
        except (IndexError, ValueError):
            score = 0
        if score < min_score:
            continue
        slug = _file_slug(url)
        if slug in seen_slugs:
            slug = slug + f"_{abs(hash(url)) % 10000}"
        seen_slugs.add(slug)
        path = out / f"{slug}.md"
        path.write_text(content)
        written.append((score, path))

    return [p for _, p in sorted(written, key=lambda t: -t[0])]
