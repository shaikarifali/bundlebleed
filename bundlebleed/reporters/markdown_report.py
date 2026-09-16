from __future__ import annotations

from pathlib import Path

from bundlebleed.models import ScanResult

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def render_markdown(result: ScanResult) -> str:
    r = result.normalized()
    lines: list[str] = [
        "# BundleBleed Scan Report",
        "",
        f"- **Scan run ID**: `{r.scan_run_id}`",
        f"- **Started at**: {r.started_at.isoformat()}",
        f"- **Targets**: {', '.join(r.targets) or '(none)'}",
        f"- **URLs collected (in scope)**: {len(r.collected_urls)}",
        f"- **URLs dropped (out of scope)**: {len(r.denied_urls)}",
        f"- **JS files downloaded**: {len(r.files)}",
    ]

    if r.graph_stats is not None:
        lines.append(
            f"- **Knowledge graph**: {r.graph_stats.node_count} nodes, "
            f"{r.graph_stats.edge_count} edges, {r.graph_stats.bundle_count} bundles"
        )

    if r.runtime_confirmed_paths:
        lines.append(
            f"- **Runtime capture**: {len(r.runtime_confirmed_paths)} request path(s) "
            "actually observed while rendering collected pages"
        )

    if r.scan_diff is not None:
        diff = r.scan_diff
        lines += ["", "## Changes since last scan", ""]
        lines.append(f"- Compared against scan started {diff.previous_started_at.isoformat()}")
        lines.append(
            f"- Endpoints: +{len(diff.new_endpoints)} new, -{len(diff.removed_endpoints)} removed"
        )
        lines.append(
            f"- Secrets: +{len(diff.new_secrets)} new, -{len(diff.removed_secrets)} removed"
        )
        lines.append(
            f"- Subdomains: +{len(diff.new_subdomains)} new, "
            f"-{len(diff.removed_subdomains)} removed"
        )
        if diff.access_control_regressions:
            lines.append("")
            lines.append(
                "**Access control regression** — reachable WITHOUT authentication now, "
                "but required an authenticated session last scan:"
            )
            lines.append("")
            for value in diff.access_control_regressions:
                lines.append(f"- `{value}`")

    lines += ["", "## Hypotheses", ""]

    if not r.hypotheses:
        lines.append("_None generated._")
    else:
        lines.append(
            "This tool never tests, confirms, or rejects a hypothesis itself. "
            "`awaiting_approval` means a verification draft was written for a human to "
            "run (`bundlebleed verify record` logs the outcome); anything else stays at "
            "`ready_to_test` until a human acts on it."
        )
        lines.append("")
        lines.append("| Risk | Confidence | Status | Bug classes | Target | Proposed test |")
        lines.append("|---|---|---|---|---|---|")
        risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        for h in sorted(r.hypotheses, key=lambda h: (risk_order.get(h.risk, 99), -h.confidence)):
            bug_classes = ", ".join(h.bug_classes)
            lines.append(
                f"| {h.risk} | {h.confidence:.2f} | {h.status.value} | {bug_classes} "
                f"| `{h.target_value}` | {h.proposed_test} |"
            )

    lines += ["", "## Secrets", ""]

    if not r.secrets:
        lines.append("_None found._")
    else:
        lines.append("| Type | Severity | Redacted value | Source |")
        lines.append("|---|---|---|---|")
        for s in sorted(r.secrets, key=lambda s: _SEVERITY_ORDER.get(s.severity, 99)):
            lines.append(
                f"| {s.secret_type} | {s.severity} | `{s.redacted_value}` | {s.source_url} |"
            )

    lines += ["", "## Endpoints", ""]

    if not r.endpoints:
        lines.append("_None found._")
    else:
        lines.append("| Value | Pattern | Source |")
        lines.append("|---|---|---|")
        for e in r.endpoints:
            lines.append(f"| `{e.value}` | {e.pattern_name} | {e.source_url} |")

    if r.endpoint_schema_discrepancy is not None and r.endpoint_schema_discrepancy.js_body_only:
        lines += [
            "",
            "**Only visible after downloading the JS body** (undetectable from "
            "the raw URL string alone):",
            "",
        ]
        for value in r.endpoint_schema_discrepancy.js_body_only:
            lines.append(f"- `{value}`")

    lines += ["", "## Subdomains", ""]

    if not r.subdomains:
        lines.append("_None found._")
    else:
        lines.append("| Domain | In scope | Note | Source |")
        lines.append("|---|---|---|---|")
        for sd in r.subdomains:
            lines.append(f"| {sd.domain} | {sd.in_scope} | {sd.note} | {sd.source_url} |")

    lines += ["", "## Parameters", ""]

    if not r.parameters:
        lines.append("_None found._")
    else:
        lines.append("| Name | Source |")
        lines.append("|---|---|")
        for p in r.parameters:
            lines.append(f"| `{p.name}` | {p.source_url} |")

    lines += ["", "## DOM findings", ""]

    if not r.dom_findings:
        lines.append("_None found._")
    else:
        lines.append("| Sink | Co-occurring sources | Source |")
        lines.append("|---|---|---|")
        for d in r.dom_findings:
            sources = ", ".join(d.co_occurring_sources)
            lines.append(f"| {d.sink_pattern} (`{d.sink_value}`) | {sources} | {d.source_url} |")

    lines += ["", "## CORS misconfigurations", ""]

    if not r.cors_findings:
        lines.append("_None found._")
    else:
        lines.append("| Source | Allow-Origin | Allow-Credentials |")
        lines.append("|---|---|---|")
        for c in r.cors_findings:
            lines.append(f"| {c.source_url} | {c.allow_origin} | {c.allow_credentials} |")

    lines += ["", "## Third-party scripts", ""]

    if not r.third_party_scripts:
        lines.append("_None found._")
    else:
        lines.append("| Hostname | Script URL | Page |")
        lines.append("|---|---|---|")
        for t in r.third_party_scripts:
            lines.append(f"| {t.hostname} | {t.script_url} | {t.page_url} |")

    lines += ["", "## PostMessage findings", ""]

    if not r.postmessage_findings:
        lines.append("_None found._")
    else:
        lines.append("| Source | Snippet |")
        lines.append("|---|---|")
        for pm in r.postmessage_findings:
            lines.append(f"| {pm.source_url} | `{pm.snippet_preview}` |")

    lines += ["", "## WebSocket findings", ""]

    if not r.websocket_findings:
        lines.append("_None found._")
    else:
        lines.append("| Source | Snippet |")
        lines.append("|---|---|")
        for w in r.websocket_findings:
            lines.append(f"| {w.source_url} | `{w.snippet_preview}` |")

    lines += ["", "## Mass assignment findings", ""]

    if not r.mass_assignment_findings:
        lines.append("_None found._")
    else:
        lines.append("| Field | Severity | Source |")
        lines.append("|---|---|---|")
        for ma in r.mass_assignment_findings:
            lines.append(f"| {ma.field_name} | {ma.severity} | {ma.source_url} |")

    lines += ["", "## Vulnerable libraries", ""]

    if not r.vulnerable_libraries:
        lines.append("_None found._")
    else:
        lines.append("| Library | Version | Vulnerable below | CVE | Severity | Source |")
        lines.append("|---|---|---|---|---|---|")
        for lib in r.vulnerable_libraries:
            lines.append(
                f"| {lib.library_name} | {lib.detected_version} | {lib.vulnerable_below} "
                f"| {lib.cve} | {lib.severity} | {lib.source_url} |"
            )

    lines += ["", "## GraphQL operations", ""]

    if not r.graphql_operations:
        lines.append("_None found._")
    else:
        lines.append("| Type | Name | Source |")
        lines.append("|---|---|---|")
        for op in r.graphql_operations:
            lines.append(f"| {op.operation_type} | {op.operation_name} | {op.source_url} |")

    lines += ["", "## Files analyzed", ""]

    if not r.files:
        lines.append("_None downloaded._")
    else:
        lines.append(
            "| URL | Frameworks | Source map found | Session | Runtime | Recovered source |"
        )
        lines.append("|---|---|---|---|---|---|")
        for f in r.files:
            frameworks = ", ".join(f.frameworks) or "-"
            session_label = f.discovered_via_session or "-"
            lines.append(
                f"| {f.url} | {frameworks} | {f.source_map_found} | {session_label} "
                f"| {f.discovered_via_runtime} | {f.recovered_from_source_map} |"
            )

    lines += ["", "## AI endpoint analysis", ""]

    if r.ai_injection_flags:
        lines.append(
            f"**{len(r.ai_injection_flags)} evidence item(s) looked like a prompt-injection "
            "attempt** embedded in scanned content. They were reported, not obeyed:"
        )
        lines.append("")
        for value in r.ai_injection_flags:
            lines.append(f"- `{value}`")
        lines.append("")

    if not r.ai_verdicts:
        lines.append("_No AI analysis run._")
    else:
        lines.append("| Priority | Bug classes | Endpoint | Confidence | Test plan | Model |")
        lines.append("|---|---|---|---|---|---|")
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        for v in sorted(r.ai_verdicts, key=lambda v: priority_order.get(v.priority, 99)):
            bug_classes = ", ".join(v.bug_classes)
            lines.append(
                f"| {v.priority} | {bug_classes} | `{v.endpoint_value}` | {v.confidence:.2f} "
                f"| {v.test_plan} | {v.model} ({v.prompt_version}) |"
            )

    lines.append("")
    return "\n".join(lines)


def write_markdown_report(result: ScanResult, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "scan-result.md"
    path.write_text(render_markdown(result))
    return path
