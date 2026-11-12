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

    # ── R1: JavaScript intelligence ──────────────────────────────────────────
    lines += ["", "## Entropy secrets", ""]
    if not r.entropy_secrets:
        lines.append("_None found._")
    else:
        lines.append(f"**{len(r.entropy_secrets)} high-entropy token(s)** — manual review needed")
        lines.append("")
        lines.append("| Entropy | Redacted | Partial SHA256 | Line | Source |")
        lines.append("|---|---|---|---|---|")
        for e in sorted(r.entropy_secrets, key=lambda e: -e.entropy_score)[:30]:
            lines.append(
                f"| {e.entropy_score:.2f} | `{e.redacted_value}` | `{e.partial_hash}` "
                f"| {e.line} | {e.source_url} |"
            )
        if len(r.entropy_secrets) > 30:
            lines.append(f"_... {len(r.entropy_secrets) - 30} more (see findings/secrets.md)_")

    lines += ["", "## Interesting comments", ""]
    if not r.interesting_comments:
        lines.append("_None found._")
    else:
        lines.append(f"**{len(r.interesting_comments)} comment(s)** containing security keywords")
        lines.append("")
        lines.append("| Keyword | Comment | Line | Source |")
        lines.append("|---|---|---|---|")
        for c in r.interesting_comments[:20]:
            lines.append(
                f"| `{c.keyword_matched}` | `{c.text[:80]}` | {c.line} | {c.source_url} |"
            )
        if len(r.interesting_comments) > 20:
            lines.append(f"_... {len(r.interesting_comments) - 20} more_")

    lines += ["", "## Feature flags", ""]
    if not r.feature_flags:
        lines.append("_None found._")
    else:
        lines.append(f"**{len(r.feature_flags)} feature flag(s)** detected")
        lines.append("")
        lines.append("| Key | Value hint | Line | Source |")
        lines.append("|---|---|---|---|")
        for f in r.feature_flags[:20]:
            lines.append(f"| `{f.key}` | `{f.value_hint}` | {f.line} | {f.source_url} |")

    lines += ["", "## Vulnerable libraries", ""]
    if not r.vulnerable_libraries:
        lines.append("_None found._")
    else:
        lines.append(f"**{len(r.vulnerable_libraries)} library/libraries** with known CVEs")
        lines.append("")
        lines.append("| Library | Version | CVEs | Source |")
        lines.append("|---|---|---|---|")
        for v in r.vulnerable_libraries:
            cves = ", ".join(v.cves[:3]) or "-"
            lines.append(f"| {v.name} | {v.version} | {cves} | {v.file} |")

    lines += ["", "## API groups", ""]
    if not r.api_groups:
        lines.append("_None found._")
    else:
        for g in r.api_groups:
            old_note = f" _(legacy: {', '.join(g.old_versions[:3])})_" if g.old_versions else ""
            lines.append(f"**{g.group_name}**{old_note}: {len(g.endpoints)} endpoint(s)")
        lines.append("")

    # ── R2: API security intelligence ────────────────────────────────────────
    lines += ["", "## GraphQL operations", ""]
    if not r.graphql_operations:
        lines.append("_None found._")
    else:
        lines.append(f"**{len(r.graphql_operations)} operation(s)** detected")
        lines.append("")
        lines.append("| Type | Name | Variables | Persisted | Endpoint |")
        lines.append("|---|---|---|---|---|")
        for op in r.graphql_operations[:20]:
            vars_str = ", ".join(f"`{v}`" for v in op.variables[:4])
            lines.append(
                f"| {op.op_type} | `{op.op_name}` | {vars_str or '-'} "
                f"| {'✓' if op.is_persisted else '-'} | `{op.endpoint}` |"
            )

    lines += ["", "## WebSocket findings", ""]
    if not r.websocket_findings:
        lines.append("_None found._")
    else:
        lines.append(f"**{len(r.websocket_findings)} WebSocket/real-time endpoint(s)**")
        lines.append("")
        lines.append("| Endpoint | Protocol | Auth in URL | Origin check | Line | Source |")
        lines.append("|---|---|---|---|---|---|")
        for ws in r.websocket_findings:
            auth_flag = "⚠️ YES" if ws.auth_in_url else "no"
            origin_flag = "✓" if ws.has_origin_check else "⚠️ no"
            lines.append(
                f"| `{ws.endpoint}` | {ws.protocol} | {auth_flag} "
                f"| {origin_flag} | {ws.line} | {ws.source_url} |"
            )

    lines += ["", "## Auth configuration findings", ""]
    if not r.auth_findings:
        lines.append("_None found._")
    else:
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        lines.append(f"**{len(r.auth_findings)} signal(s)**")
        lines.append("")
        lines.append("| Type | Severity | Detail | Line | Source |")
        lines.append("|---|---|---|---|---|")
        for af in sorted(r.auth_findings, key=lambda af: sev_order.get(af.severity_candidate, 99)):
            lines.append(
                f"| `{af.finding_type}` | {af.severity_candidate} | {af.detail[:80]} "
                f"| {af.line} | {af.source_url} |"
            )

    lines += ["", "## Access control candidates (BOLA / BFLA / mass assignment)", ""]
    if not r.object_access_candidates:
        lines.append("_None found._")
    else:
        lines.append(f"**{len(r.object_access_candidates)} candidate(s)** — manual verification required")
        lines.append("")
        lines.append("| Bug class | Level | Endpoint | Identifier | Function | Source |")
        lines.append("|---|---|---|---|---|---|")
        for c in r.object_access_candidates[:30]:
            fn = c.function_name or "-"
            lines.append(
                f"| **{c.bug_class}** | {c.level} | `{c.endpoint}` | `{c.identifier}` "
                f"| `{fn}` | {c.source_url} |"
            )
        if len(r.object_access_candidates) > 30:
            lines.append(f"_... {len(r.object_access_candidates) - 30} more_")

    # ── R3: Advanced client-side security ────────────────────────────────────
    lines += ["", "## DOM taint findings", ""]
    if not r.dom_taint_findings:
        lines.append("_None found._")
    else:
        lines.append(
            f"**{len(r.dom_taint_findings)} source-to-sink chain(s)** — "
            "proximity-based, not guaranteed data flow; manual triage required"
        )
        lines.append("")
        lines.append("| Source | Line | Sink | Line | Category | Source file |")
        lines.append("|---|---|---|---|---|---|")
        for d in r.dom_taint_findings[:20]:
            lines.append(
                f"| `{d.source_name}` | {d.source_line} | `{d.sink_name}` "
                f"| {d.sink_line} | {d.sink_category} | {d.source_url} |"
            )

    lines += ["", "## Prototype pollution findings", ""]
    if not r.proto_pollution_findings:
        lines.append("_None found._")
    else:
        lines.append(f"**{len(r.proto_pollution_findings)} pollution pattern(s)**")
        lines.append("")
        lines.append("| Level | Pattern | Detail | Line | Source |")
        lines.append("|---|---|---|---|---|")
        for p in r.proto_pollution_findings[:20]:
            lines.append(
                f"| L{p.level} | `{p.pattern_name}` | {p.detail[:60]} "
                f"| {p.line} | {p.source_url} |"
            )

    lines += ["", "## postMessage findings", ""]
    if not r.postmessage_findings:
        lines.append("_None found._")
    else:
        lines.append(f"**{len(r.postmessage_findings)} postMessage sender(s)/receiver(s)**")
        lines.append("")
        lines.append("| Kind | Target origin | Origin check | Sinks | Line | Source |")
        lines.append("|---|---|---|---|---|---|")
        for pm in r.postmessage_findings:
            origin = f"`{pm.target_origin}`" if pm.target_origin else "-"
            if pm.target_origin == "*":
                origin += " ⚠️"
            check = "✓" if pm.has_origin_check else ("⚠️ no" if pm.kind == "receiver" else "-")
            sinks = ", ".join(pm.data_sinks[:3]) if pm.data_sinks else "-"
            lines.append(
                f"| {pm.kind} | {origin} | {check} | {sinks} | {pm.line} | {pm.source_url} |"
            )

    lines += ["", "## Worker findings", ""]
    if not r.worker_findings:
        lines.append("_None found._")
    else:
        lines.append(f"**{len(r.worker_findings)} worker reference(s)**")
        lines.append("")
        lines.append("| Type | URL | Fetch intercept | Blob | Skip-waiting | Source |")
        lines.append("|---|---|---|---|---|---|")
        for w in r.worker_findings:
            wurl = f"`{w.worker_url}`" if w.worker_url else "_(dynamic)_"
            blob = "⚠️ yes" if w.is_inline_blob else "no"
            fetch = "⚠️ yes" if w.has_fetch_intercept else "no"
            skip_w = getattr(w, "has_skip_waiting", False)
            skip = "yes" if skip_w else "no"
            lines.append(
                f"| {w.worker_type} | {wurl} | {fetch} | {blob} | {skip} | {w.source_url} |"
            )

    lines += ["", "## Asset graph", ""]
    if not r.asset_graph_nodes:
        lines.append("_No chunk graph data._")
    else:
        lines.append(f"**{len(r.asset_graph_nodes)} chunk(s)**")
        lines.append("")
        lines.append("| Chunk URL | Name | Bundler | Dynamic imports | Source |")
        lines.append("|---|---|---|---|---|")
        for n in r.asset_graph_nodes[:20]:
            name = f"`{n.chunk_name}`" if n.chunk_name else "-"
            dyn = str(len(n.dynamic_imports)) if n.dynamic_imports else "0"
            lines.append(
                f"| `{n.chunk_url}` | {name} | {n.bundler} | {dyn} | {n.source_url} |"
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
