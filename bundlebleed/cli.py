from __future__ import annotations

import asyncio
import json
import os
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated
from urllib.parse import urlsplit

import typer

from bundlebleed import __version__
from bundlebleed.ai.evidence import build_evidence_items, flagged_values, render_evidence_bundle
from bundlebleed.ai.prompt_loader import load_endpoint_analysis_prompt
from bundlebleed.ai.providers.anthropic import AnthropicProvider
from bundlebleed.ai.providers.base import LLMProvider
from bundlebleed.ai.providers.ollama import OllamaProvider
from bundlebleed.ai.providers.openrouter import OpenRouterProvider
from bundlebleed.ai.tasks.attack_chains import suggest_attack_chains
from bundlebleed.ai.tasks.endpoint_intel import classify_endpoints
from bundlebleed.ai.tasks.report_writer import draft_report
from bundlebleed.auth.cookies import parse_cookie_file
from bundlebleed.auth.crawler import fetch_authenticated_script_urls
from bundlebleed.auth.models import AuthSession
from bundlebleed.auth.parser import load_auth_sessions_from_scope_yaml, parse_session_arg
from bundlebleed.collectors.orchestrator import active_scan_authorized, collect_all
from bundlebleed.config import BundleBleedConfig, load_app_config
from bundlebleed.downloader.fetcher import fetch_js_files, fetch_page_files, looks_like_js
from bundlebleed.downloader.http_client import GuardedHttpClient
from bundlebleed.evidence.store import (
    load_hypothesis,
    record_verification_outcome,
    write_attack_chains,
    write_evidence_store,
    write_report_draft,
)
from bundlebleed.extractors.cors import extract_cors_misconfiguration
from bundlebleed.extractors.dom_analysis import extract_dom_findings
from bundlebleed.extractors.endpoints import extract_endpoints
from bundlebleed.extractors.html_links import extract_html_endpoints, extract_third_party_scripts
from bundlebleed.extractors.parameters import extract_parameters
from bundlebleed.extractors.secrets import extract_secrets
from bundlebleed.extractors.subdomains import extract_subdomains
from bundlebleed.history.diff import compute_scan_diff
from bundlebleed.history.snapshots import load_latest_snapshot, save_snapshot
from bundlebleed.hypotheses.engine import generate_hypotheses
from bundlebleed.hypotheses.models import HypothesisStatus
from bundlebleed.knowledge.export import write_graph_export
from bundlebleed.knowledge.graph import build_graph, graph_stats
from bundlebleed.knowledge.schema import endpoint_schema_discrepancy
from bundlebleed.logging import configure_logging
from bundlebleed.models import (
    Endpoint,
    FetchedFile,
    FileAnalysis,
    ScanResult,
)
from bundlebleed.monitoring.formatter import format_slack_payload, has_changes
from bundlebleed.monitoring.webhook import post_webhook
from bundlebleed.processors.beautifier import beautify
from bundlebleed.processors.framework_detect import detect_frameworks
from bundlebleed.ratelimit import RateLimiter
from bundlebleed.reporters.html_dashboard import write_html_report
from bundlebleed.reporters.json_report import write_json_report
from bundlebleed.reporters.markdown_report import write_markdown_report
from bundlebleed.reporters.wordlists import write_wordlists
from bundlebleed.runtime.browser import PlaywrightNotInstalledError, capture_runtime
from bundlebleed.runtime.models import RuntimeCapture
from bundlebleed.scope.guard import ScopeGuard
from bundlebleed.scope.models import ScopeConfig
from bundlebleed.scope.parser import load_scope_config
from bundlebleed.scope.validator import is_in_scope
from bundlebleed.verification.artifacts import write_verification_artifacts
from bundlebleed.verification.differential import ResponseCapture, compare_responses
from bundlebleed.verification.drafter import draft_verification

# -h alongside --help everywhere -- every other recon tool a bug hunter
# already has muscle memory for (nmap, ffuf, katana, nuclei, httpx) supports
# the short form; Typer/Click only wires up --help unless told to.
_HELP_OPTION_NAMES = {"help_option_names": ["-h", "--help"]}

_BANNER_ART = r"""
 ____                  _ _      ____  _               _
| __ ) _   _ _ __   __| | | ___| __ )| | ___  ___  __| |
|  _ \| | | | '_ \ / _` | |/ _ \  _ \| |/ _ \/ _ \/ _` |
| |_) | |_| | | | | (_| | |  __/ |_) | |  __/  __/ (_| |
|____/ \__,_|_| |_|\__,_|_|\___|____/|_|\___|\___|\__,_|
"""


def _print_banner() -> None:
    """Printed once per invocation, to stderr -- never stdout, so piping a
    scan's own echoed output (or redirecting it to a file) is never
    polluted by this. Colored only when stderr is an actual terminal."""
    tagline = (
        f"  Scope-gated JS recon for authorized bug bounty testing  ·  v{__version__}\n"
        "  Passive-by-default  ·  human-verified  ·  no exploitation, ever\n"
    )
    if sys.stderr.isatty():
        print(f"\033[36m{_BANNER_ART}\033[0m{tagline}", file=sys.stderr)
    else:
        print(_BANNER_ART + tagline, file=sys.stderr)


app = typer.Typer(
    help="BundleBleed — scope-gated JS recon for authorized bug bounty testing.",
    context_settings=_HELP_OPTION_NAMES,
)
scope_app = typer.Typer(
    help="Inspect and validate scope without running a scan.",
    context_settings=_HELP_OPTION_NAMES,
)
verify_app = typer.Typer(
    help="Draft and record manual verification of hypotheses.",
    context_settings=_HELP_OPTION_NAMES,
)
ai_app = typer.Typer(
    help="AI tasks operating on an existing scan's evidence store.",
    context_settings=_HELP_OPTION_NAMES,
)
app.add_typer(scope_app, name="scope")
app.add_typer(verify_app, name="verify")
app.add_typer(ai_app, name="ai")


def _resolve_provider(
    provider_name: str,
    model: str,
    host: str | None,
    provider_flag: str = "--provider",
    host_flag: str = "--host",
) -> LLMProvider:
    """Shared 3-way (anthropic/ollama/openrouter) provider construction used
    by every AI-invoking CLI command, so the validation and error messages
    stay identical everywhere. Exits the CLI on a configuration error."""
    if provider_name not in ("anthropic", "ollama", "openrouter"):
        typer.echo(
            f"error: {provider_flag} must be 'anthropic', 'ollama', or 'openrouter', "
            f"got {provider_name!r}",
            err=True,
        )
        raise typer.Exit(code=1)

    if provider_name == "ollama":
        if not host:
            typer.echo(
                f"error: {host_flag} is required with {provider_flag} ollama (never "
                "guessed or defaulted to a possibly-wrong address)",
                err=True,
            )
            raise typer.Exit(code=1)
        return OllamaProvider(model=model, host=host)

    if provider_name == "openrouter":
        openrouter_key = os.environ.get("OPENROUTER_API_KEY")
        if not openrouter_key:
            typer.echo(
                f"error: OPENROUTER_API_KEY must be set to run {provider_flag} openrouter "
                "(never pass a key via config or CLI flag)",
                err=True,
            )
            raise typer.Exit(code=1)
        return OpenRouterProvider(model=model, api_key=openrouter_key)

    if not os.environ.get("ANTHROPIC_API_KEY"):
        typer.echo(
            "error: ANTHROPIC_API_KEY must be set to use the default 'anthropic' provider "
            "(never pass a key via config or CLI flag)",
            err=True,
        )
        raise typer.Exit(code=1)
    return AnthropicProvider(model=model)


def _read_seed_url_file(path: Path) -> list[str]:
    return [
        stripped
        for line in path.read_text().splitlines()
        if (stripped := line.strip()) and not stripped.startswith("#")
    ]


async def _collect_and_fetch(
    targets: list[str],
    scope_config: ScopeConfig,
    guard: ScopeGuard,
    app_config: BundleBleedConfig,
    cli_active_flag: bool,
    download: bool,
    concurrency: int,
    seed_urls: list[str] | None = None,
) -> tuple[list[str], list[str], list[FetchedFile], list[FetchedFile]]:
    """Run collection, then (unless disabled) fetch the body of every
    JS-looking allowed URL, and separately the body of every other
    (non-static-asset) page URL for link/form/parameter extraction."""
    allowed_urls, denied_urls = await collect_all(
        targets,
        scope_config,
        guard,
        app_config,
        cli_active_flag=cli_active_flag,
        seed_urls=seed_urls,
    )

    if not download:
        return allowed_urls, denied_urls, [], []

    rate_limiter = RateLimiter(scope_config.scan.requests_per_second)
    client = GuardedHttpClient(guard, rate_limiter=rate_limiter)
    try:
        fetched_js = await fetch_js_files(allowed_urls, client, concurrency=concurrency)
        fetched_pages = await fetch_page_files(allowed_urls, client, concurrency=concurrency)
    finally:
        await client.aclose()

    return allowed_urls, denied_urls, fetched_js, fetched_pages


def _chunk(items: list[Endpoint], size: int) -> list[list[Endpoint]]:
    return [items[i : i + size] for i in range(0, len(items), size)]


async def _authenticated_crawl(
    allowed_urls: list[str],
    sessions: list[AuthSession],
    guard: ScopeGuard,
    scope_config: ScopeConfig,
    unauth_js_urls: set[str],
    concurrency: int,
) -> list[tuple[FetchedFile, AuthSession]]:
    """For each session, fetch every already-collected URL WITH its cookie
    attached, extract <script src> references, and download only the JS
    files not already known from the unauthenticated crawl. Every fetch
    still goes through ScopeGuard — a session cookie never bypasses scope.
    """
    rate_limiter = RateLimiter(scope_config.scan.requests_per_second)
    client = GuardedHttpClient(guard, rate_limiter=rate_limiter)
    results: list[tuple[FetchedFile, AuthSession]] = []
    try:
        for session in sessions:
            discovered = await fetch_authenticated_script_urls(allowed_urls, session, client)
            new_urls = [u for u in discovered if u not in unauth_js_urls]
            if not new_urls:
                continue
            fetched = await fetch_js_files(new_urls, client, concurrency=concurrency)
            results.extend((f, session) for f in fetched)
    finally:
        await client.aclose()
    return results


async def _fetch_runtime_js(
    urls: list[str], guard: ScopeGuard, scope_config: ScopeConfig, concurrency: int
) -> list[FetchedFile]:
    rate_limiter = RateLimiter(scope_config.scan.requests_per_second)
    client = GuardedHttpClient(guard, rate_limiter=rate_limiter)
    try:
        return await fetch_js_files(urls, client, concurrency=concurrency)
    finally:
        await client.aclose()


_SCAN_EXAMPLES = """\
Examples:

  Single domain:
    bundlebleed scan -t example.com -o results/

  Multiple domains (comma-separated, no spaces):
    bundlebleed scan -t example.com,api.example.com,shop.example.com -o results/

  Multiple domains (from a file, one per line -- wildcards with '*.',
  exclusions with a leading '!'; see examples/scope-multi-domain.txt):
    bundlebleed scan -tL examples/scope-multi-domain.txt -o results/

  Full control (rate limiting, authorization attestation for --active,
  sessions) via a scope.yaml instead of -t/-tL:
    bundlebleed scan --config scope.yaml -o results/

  Fresh or JS-heavy target with no gau/waybackurls archive history:
    bundlebleed scan -t example.com --seed-url https://example.com/ -o results/
"""


@app.command(epilog=_SCAN_EXAMPLES)
def scan(
    target: Annotated[
        str | None,
        typer.Option(
            "-t",
            "--target",
            help="One domain, or several comma-separated with no spaces "
            "(e.g. 'example.com,api.example.com'). See examples below.",
        ),
    ] = None,
    target_list: Annotated[
        Path | None,
        typer.Option(
            "-tL",
            "--target-list",
            help="A scope.txt file, one domain per line -- for many domains at once. "
            "'*.domain.com' for a wildcard, '!domain.com' to exclude. "
            "See examples/scope-multi-domain.txt.",
        ),
    ] = None,
    config: Annotated[
        Path | None,
        typer.Option(
            "--config",
            help="A full scope.yaml instead of -t/-tL -- adds rate limiting, the "
            "authorization attestation --active needs, and session config.",
        ),
    ] = None,
    seed_url: Annotated[
        list[str] | None,
        typer.Option(
            "--seed-url",
            help="Inject a known URL directly into collection (repeatable), bypassing the "
            "need for gau/waybackurls to have found it first — essential for a freshly "
            "provisioned or JS-heavy SPA target with no archive history. Still goes through "
            "the exact same ScopeGuard check as any collector-returned URL: a seed URL "
            "outside the declared scope is denied and logged, never a bypass.",
        ),
    ] = None,
    seed_url_file: Annotated[
        Path | None,
        typer.Option(
            "--seed-url-file",
            help="Load seed URLs from a file, one per line ('#'-prefixed lines and blank "
            "lines ignored). Combined with any --seed-url values given. Same ScopeGuard "
            "check as --seed-url — nothing here bypasses scope.",
        ),
    ] = None,
    output: Annotated[Path, typer.Option("-o", "--output", help="Output directory")] = Path(
        "./results"
    ),
    active: Annotated[
        bool,
        typer.Option(
            "--active/--no-active",
            help="Enable active collectors (e.g. katana). Also requires app-config "
            "active_scan_enabled=true and scope.yaml authorization.attested=true.",
        ),
    ] = False,
    app_config_path: Annotated[
        Path | None,
        typer.Option("--app-config", help="App-level config.yaml (active_scan_enabled, etc.)"),
    ] = None,
    download: Annotated[
        bool,
        typer.Option(
            "--download/--no-download",
            help="Fetch the body of every JS-looking in-scope URL for deeper extraction "
            "(framework detection, subdomains, parameters, DOM sinks/sources), and the "
            "body of every other non-static-asset page URL for link/form/query-parameter "
            "extraction (plain page routes and form actions the JS-only patterns can't "
            "see). Still passive: plain GETs to ScopeGuard-allowed URLs, same as a "
            "browser would make.",
        ),
    ] = True,
    concurrency: Annotated[
        int, typer.Option("--concurrency", help="Max concurrent JS file downloads")
    ] = 5,
    ai: Annotated[
        bool,
        typer.Option(
            "--ai/--no-ai",
            help="Classify collected endpoints with an LLM (Anthropic). Off by default: "
            "costs money and sends endpoint metadata (never secrets or raw JS) off-machine.",
        ),
    ] = False,
    ai_model: Annotated[
        str | None,
        typer.Option(
            "--ai-model",
            help="Exact model id to use. Required with --ai — CLAUDE.md Invariant 8: "
            "models are pinned, never defaulted, so a change is a deliberate, tracked event.",
        ),
    ] = None,
    ai_provider: Annotated[
        str,
        typer.Option(
            "--ai-provider",
            help="Which LLM backend to use with --ai: 'anthropic' (default, needs "
            "ANTHROPIC_API_KEY), 'ollama' (needs --ai-host, a locally/LAN-hosted model), "
            "or 'openrouter' (needs OPENROUTER_API_KEY; several free-tier models available).",
        ),
    ] = "anthropic",
    ai_host: Annotated[
        str | None,
        typer.Option(
            "--ai-host",
            help="Ollama server URL (e.g. http://172.30.224.1:11434). Required with "
            "--ai-provider ollama — never guessed or defaulted, since a wrong host should "
            "fail loudly rather than silently try some assumed address.",
        ),
    ] = None,
    ai_batch_size: Annotated[
        int, typer.Option("--ai-batch-size", help="Endpoints per LLM call")
    ] = 20,
    ai_dry_run: Annotated[
        bool,
        typer.Option(
            "--ai-dry-run",
            help="Show what would be sent to the model (batch count, an example prompt, any "
            "flagged evidence) without making any API call or spending tokens.",
        ),
    ] = False,
    session: Annotated[
        list[str] | None,
        typer.Option(
            "--session",
            help="Authenticated session as 'name:cookie_string' (repeatable). Prefer "
            "--cookie-file over this where possible — an inline cookie string is visible "
            "in shell history and the process list. Still GET-only: no login is performed.",
        ),
    ] = None,
    cookie_file: Annotated[
        Path | None,
        typer.Option(
            "--cookie-file",
            help="Load a session's cookies from a file (raw 'k=v; k2=v2' header, a JSON "
            "[{'name','value'}, ...] array, or a Netscape cookies.txt export).",
        ),
    ] = None,
    draft_verification_flag: Annotated[
        bool,
        typer.Option(
            "--draft-verification",
            help="Draft (never send) a baseline/test request pair for IDOR-shaped hypotheses "
            "with a concrete numeric id. Requires the same 3-gate authorization as --active "
            "(app-config active_scan_enabled + this flag's sibling + scope.yaml attestation). "
            "Writes .http/curl artifacts for a human to run themselves; nothing is ever sent "
            "by this tool. Use `bundlebleed verify record` afterwards to log what you found.",
        ),
    ] = False,
    history_dir: Annotated[
        Path | None,
        typer.Option(
            "--history-dir",
            help="Save this scan's results here and diff against the most recent prior scan "
            "of the same target (new/removed endpoints, secrets, subdomains, and an "
            "access-control-regression check). Off by default — no local history is kept "
            "unless you ask for it.",
        ),
    ] = None,
    webhook: Annotated[
        str | None,
        typer.Option(
            "--webhook",
            help="Post a change summary here (Slack/Discord-compatible) when --history-dir "
            "finds a prior scan AND something changed. Silent otherwise — no ping on the "
            "first scan or when nothing changed. This URL is your own notification channel, "
            "not the target, so it is not scope-checked.",
        ),
    ] = None,
    runtime_capture: Annotated[
        bool,
        typer.Option(
            "--runtime-capture",
            help="Render collected pages in headless Chromium and record every request the "
            "page actually makes (dynamic JS chunks, real fetch/XHR calls) — every single "
            "request, including redirects, is checked against ScopeGuard and aborted if "
            "out of scope. Observation only: no clicks, no form submission, no keystrokes. "
            "If --session/--cookie-file is also given, each page is re-rendered per session "
            "with that cookie attached, so client-side routing gated on auth state (e.g. an "
            "admin panel that only lazy-loads its JS chunk for a logged-in user) renders too "
            "— any JS chunk found only in an authenticated pass is flagged the same way as an "
            "auth-only endpoint. Requires the same 3-gate active-scan authorization as "
            "--active, and the optional 'playwright' dependency "
            "(pip install 'bundlebleed[runtime]').",
        ),
    ] = False,
    runtime_max_pages: Annotated[
        int, typer.Option("--runtime-max-pages", help="Cap how many pages get rendered")
    ] = 10,
    runtime_timeout: Annotated[
        float, typer.Option("--runtime-timeout", help="Per-page hard timeout, in seconds")
    ] = 15.0,
) -> None:
    """Passive-by-default scan: collect JS-referencing URLs, filter through
    ScopeGuard, download+beautify+analyze JS bodies, extract candidate
    endpoints/secrets/subdomains/parameters/DOM findings, and write reports.
    No requests are ever sent for a target that ScopeGuard denies."""
    try:
        scope_config = load_scope_config(target, target_list, config)
    except ValueError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from None

    if not scope_config.in_scope:
        typer.echo("error: scope has no in-scope entries", err=True)
        raise typer.Exit(code=1)

    sessions: list[AuthSession] = []
    try:
        for raw_session in session or []:
            sessions.append(parse_session_arg(raw_session))
        if cookie_file is not None:
            sessions.append(
                AuthSession(name="file", role="user", cookie_header=parse_cookie_file(cookie_file))
            )
        if config is not None:
            sessions.extend(load_auth_sessions_from_scope_yaml(config))
    except ValueError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from None

    app_config = load_app_config(app_config_path)
    scan_run_id = str(uuid.uuid4())
    configure_logging(scan_run_id)

    guard = ScopeGuard(
        scope_config,
        audit_log_path=output / "audit_log.jsonl",
        scan_run_id=scan_run_id,
    )

    targets = [entry.domain for entry in scope_config.in_scope]

    seed_urls = list(seed_url or [])
    if seed_url_file is not None:
        seed_urls.extend(_read_seed_url_file(seed_url_file))

    allowed_urls, denied_urls, fetched_files, fetched_pages = asyncio.run(
        _collect_and_fetch(
            targets, scope_config, guard, app_config, active, download, concurrency, seed_urls
        )
    )

    auth_fetched: list[tuple[FetchedFile, AuthSession]] = []
    if sessions and not download:
        typer.echo("note: --session/--cookie-file given but --no-download set; skipping")
    elif sessions:
        unauth_js_urls = {f.url for f in fetched_files}
        auth_fetched = asyncio.run(
            _authenticated_crawl(
                allowed_urls, sessions, guard, scope_config, unauth_js_urls, concurrency
            )
        )

    runtime_captures: list[RuntimeCapture] = []
    auth_runtime_captures: list[RuntimeCapture] = []
    if runtime_capture:
        if not active_scan_authorized(app_config, scope_config, active):
            typer.echo(
                "note: --runtime-capture given but not authorized (needs --active + "
                "active_scan_enabled + scope.yaml attestation); skipping"
            )
        else:
            candidate_pages = [u for u in allowed_urls if not looks_like_js(u)]
            try:
                runtime_captures = asyncio.run(
                    capture_runtime(
                        candidate_pages,
                        guard,
                        max_pages=runtime_max_pages,
                        timeout_seconds=runtime_timeout,
                    )
                )
                # A logged-out browser never lazy-loads an admin-only route's
                # JS chunk in the first place -- rerun the same pages WITH
                # each session's cookie so client-side routing that's gated
                # on auth state actually renders, and whatever it chunk-loads
                # is captured too. Still no login is performed: the cookie
                # must already be provided.
                for sess in sessions:
                    auth_runtime_captures.extend(
                        asyncio.run(
                            capture_runtime(
                                candidate_pages,
                                guard,
                                max_pages=runtime_max_pages,
                                timeout_seconds=runtime_timeout,
                                cookie_header=sess.cookie_header,
                                session_name=sess.name,
                            )
                        )
                    )
            except PlaywrightNotInstalledError as exc:
                typer.echo(f"note: --runtime-capture skipped: {exc}")

    url_endpoints: list[Endpoint] = []
    secrets = []
    parameters = []
    for url in allowed_urls:
        url_endpoints.extend(extract_endpoints(url, source_url=url))
        secrets.extend(extract_secrets(url, source_url=url))
        parameters.extend(extract_parameters(url, source_url=url))

    body_endpoints: list[Endpoint] = []
    files = []
    subdomains = []
    dom_findings = []
    cors_findings = []
    third_party_scripts = []
    for fetched in fetched_files:
        beautified = beautify(fetched.content)

        body_endpoints.extend(extract_endpoints(beautified, source_url=fetched.url))
        secrets.extend(extract_secrets(beautified, source_url=fetched.url))
        subdomains.extend(extract_subdomains(beautified, fetched.url, scope_config))
        parameters.extend(extract_parameters(beautified, source_url=fetched.url))
        dom_findings.extend(extract_dom_findings(beautified, source_url=fetched.url))
        cors_finding = extract_cors_misconfiguration(fetched.headers, fetched.url)
        if cors_finding is not None:
            cors_findings.append(cors_finding)

        files.append(
            FileAnalysis(
                url=fetched.url,
                frameworks=detect_frameworks(beautified),
                source_map_found=fetched.source_map_found,
                source_map_url=fetched.source_map_url,
                recovered_from_source_map=fetched.recovered_from_source_map,
            )
        )

    for page in fetched_pages:
        body_endpoints.extend(extract_html_endpoints(page.content, page.url))
        body_endpoints.extend(extract_endpoints(page.content, source_url=page.url))
        secrets.extend(extract_secrets(page.content, source_url=page.url))
        subdomains.extend(extract_subdomains(page.content, page.url, scope_config))
        parameters.extend(extract_parameters(page.content, source_url=page.url))
        dom_findings.extend(extract_dom_findings(page.content, source_url=page.url))
        third_party_scripts.extend(extract_third_party_scripts(page.content, page.url))
        page_cors_finding = extract_cors_misconfiguration(page.headers, page.url)
        if page_cors_finding is not None:
            cors_findings.append(page_cors_finding)

    auth_only_js_urls: list[str] = []
    for fetched, sess in auth_fetched:
        beautified = beautify(fetched.content)

        body_endpoints.extend(extract_endpoints(beautified, source_url=fetched.url))
        secrets.extend(extract_secrets(beautified, source_url=fetched.url))
        subdomains.extend(extract_subdomains(beautified, fetched.url, scope_config))
        parameters.extend(extract_parameters(beautified, source_url=fetched.url))
        dom_findings.extend(extract_dom_findings(beautified, source_url=fetched.url))
        auth_cors_finding = extract_cors_misconfiguration(fetched.headers, fetched.url)
        if auth_cors_finding is not None:
            cors_findings.append(auth_cors_finding)

        files.append(
            FileAnalysis(
                url=fetched.url,
                frameworks=detect_frameworks(beautified),
                source_map_found=fetched.source_map_found,
                source_map_url=fetched.source_map_url,
                discovered_via_session=sess.name,
                recovered_from_source_map=fetched.recovered_from_source_map,
            )
        )
        auth_only_js_urls.append(fetched.url)

    all_runtime_captures = runtime_captures + auth_runtime_captures
    runtime_confirmed_paths: list[str] = []
    for capture in all_runtime_captures:
        for event in capture.events:
            if event.allowed:
                runtime_confirmed_paths.append(urlsplit(event.url).path)

    if all_runtime_captures:
        known_js_urls = {f.url for f in fetched_files} | {f.url for f, _ in auth_fetched}
        unauth_runtime_js_urls = {u for c in runtime_captures for u in c.discovered_js_urls}

        # A chunk found in the logged-out pass too isn't auth-gated, even if
        # an authenticated pass also happened to load it.
        auth_only_session_by_url: dict[str, str] = {}
        for capture in auth_runtime_captures:
            for url in capture.discovered_js_urls:
                if url not in known_js_urls and url not in unauth_runtime_js_urls:
                    auth_only_session_by_url.setdefault(url, capture.session_name or "")

        new_runtime_js_urls = sorted(unauth_runtime_js_urls - known_js_urls)
        auth_only_runtime_js_urls = sorted(auth_only_session_by_url)

        for urls, tag_session in (
            (new_runtime_js_urls, False),
            (auth_only_runtime_js_urls, True),
        ):
            if not urls:
                continue
            runtime_fetched = asyncio.run(_fetch_runtime_js(urls, guard, scope_config, concurrency))
            for fetched in runtime_fetched:
                beautified = beautify(fetched.content)

                body_endpoints.extend(extract_endpoints(beautified, source_url=fetched.url))
                secrets.extend(extract_secrets(beautified, source_url=fetched.url))
                subdomains.extend(extract_subdomains(beautified, fetched.url, scope_config))
                parameters.extend(extract_parameters(beautified, source_url=fetched.url))
                dom_findings.extend(extract_dom_findings(beautified, source_url=fetched.url))
                runtime_cors_finding = extract_cors_misconfiguration(fetched.headers, fetched.url)
                if runtime_cors_finding is not None:
                    cors_findings.append(runtime_cors_finding)

                files.append(
                    FileAnalysis(
                        url=fetched.url,
                        frameworks=detect_frameworks(beautified),
                        source_map_found=fetched.source_map_found,
                        source_map_url=fetched.source_map_url,
                        discovered_via_runtime=True,
                        discovered_via_session=(
                            auth_only_session_by_url.get(fetched.url) if tag_session else None
                        ),
                        recovered_from_source_map=fetched.recovered_from_source_map,
                    )
                )
                if tag_session:
                    auth_only_js_urls.append(fetched.url)

    endpoints = url_endpoints + body_endpoints

    result = ScanResult(
        scan_run_id=scan_run_id,
        started_at=datetime.now(UTC),
        targets=targets,
        collected_urls=allowed_urls,
        denied_urls=denied_urls,
        endpoints=endpoints,
        secrets=secrets,
        files=files,
        subdomains=subdomains,
        parameters=parameters,
        dom_findings=dom_findings,
        cors_findings=cors_findings,
        third_party_scripts=third_party_scripts,
        endpoint_schema_discrepancy=endpoint_schema_discrepancy(url_endpoints, body_endpoints),
        auth_only_js_urls=auth_only_js_urls,
        runtime_confirmed_paths=runtime_confirmed_paths,
    )

    history_key = ",".join(sorted(targets))
    previous_snapshot = None
    if history_dir is not None:
        previous_snapshot = load_latest_snapshot(history_dir, history_key)
        if previous_snapshot is not None:
            result.historical_endpoint_values = [e.value for e in previous_snapshot.endpoints]
            result.scan_diff = compute_scan_diff(previous_snapshot, result)

    graph = build_graph(result)
    result.graph_stats = graph_stats(graph)
    graph_path = write_graph_export(graph, output)

    if ai:
        if not ai_model:
            typer.echo(
                "error: --ai-model is required with --ai (models must be explicitly "
                "pinned, never defaulted)",
                err=True,
            )
            raise typer.Exit(code=1)

        if ai_dry_run:
            batches = _chunk(endpoints, ai_batch_size)
            all_items = build_evidence_items(endpoints)
            result.ai_injection_flags = flagged_values(all_items)
            typer.echo(
                f"[ai-dry-run] would send {len(endpoints)} endpoints in "
                f"{len(batches)} batch(es) of up to {ai_batch_size} to model={ai_model}"
            )
            if result.ai_injection_flags:
                typer.echo(
                    f"[ai-dry-run] {len(result.ai_injection_flags)} evidence item(s) "
                    "flagged as possible prompt-injection attempts"
                )
            if batches:
                preview_bundle = render_evidence_bundle(build_evidence_items(batches[0]))
                user_template = load_endpoint_analysis_prompt()
                typer.echo("[ai-dry-run] example prompt for batch 1:")
                typer.echo(user_template.text.format(evidence_bundle=preview_bundle))
            typer.echo("[ai-dry-run] no API calls made, no tokens spent")
        else:
            provider = _resolve_provider(
                ai_provider, ai_model, ai_host, provider_flag="--ai-provider", host_flag="--ai-host"
            )
            ai_result = asyncio.run(
                classify_endpoints(endpoints, provider, batch_size=ai_batch_size)
            )
            result.ai_verdicts = ai_result.verdicts
            result.ai_injection_flags = ai_result.injection_flags
            typer.echo(
                f"AI: {len(ai_result.verdicts)} endpoint verdicts from "
                f"provider={ai_provider} model={ai_model}"
            )
            if ai_result.injection_flags:
                typer.echo(
                    f"AI: {len(ai_result.injection_flags)} evidence item(s) flagged as "
                    "possible prompt-injection attempts (reported, not obeyed)"
                )

    result.hypotheses = generate_hypotheses(result)

    drafted_count = 0
    if draft_verification_flag:
        session_for_url = {
            f.url: f.discovered_via_session for f in files if f.discovered_via_session
        }
        updated_hypotheses = []
        for hyp in result.hypotheses:
            draft = draft_verification(
                hyp,
                app_config,
                scope_config,
                active,
                session_role_hint=session_for_url.get(hyp.source_url),
            )
            if draft is None:
                updated_hypotheses.append(hyp)
                continue
            write_verification_artifacts(draft, output)
            drafted_count += 1
            updated_hypotheses.append(
                hyp.model_copy(update={"status": HypothesisStatus.AWAITING_APPROVAL})
            )
        result.hypotheses = updated_hypotheses
        if drafted_count == 0:
            typer.echo(
                "note: --draft-verification given but nothing was eligible (needs full "
                "active-scan authorization + an IDOR hypothesis with a concrete numeric id)"
            )

    evidence_paths = write_evidence_store(result.hypotheses, output)

    snapshot_path = None
    if history_dir is not None:
        snapshot_path = save_snapshot(result, history_dir, history_key)

    json_path = write_json_report(result, output)
    md_path = write_markdown_report(result, output)
    html_path = write_html_report(result, output)
    wordlist_paths = write_wordlists(result, output)

    typer.echo(
        f"collected {len(allowed_urls)} in-scope URLs, dropped {len(denied_urls)} out-of-scope"
    )
    recovered_count = sum(1 for f in fetched_files if f.recovered_from_source_map)
    typer.echo(
        f"downloaded {len(fetched_files) - recovered_count} JS files "
        f"({recovered_count} original source file(s) recovered from source maps), "
        f"{len(fetched_pages)} page bodies"
    )
    if sessions:
        typer.echo(
            f"authenticated crawl ({len(sessions)} session(s): "
            f"{', '.join(s.name for s in sessions)}): "
            f"{len(auth_only_js_urls)} JS file(s) only visible when authenticated"
        )
    if runtime_captures:
        total_events = sum(len(c.events) for c in runtime_captures)
        blocked = sum(1 for c in runtime_captures for e in c.events if not e.allowed)
        typer.echo(
            f"runtime capture: {len(runtime_captures)} page(s) rendered, {total_events} "
            f"request(s) observed ({blocked} out-of-scope, aborted), "
            f"{len(runtime_confirmed_paths)} path(s) confirmed"
        )
    typer.echo(f"found {len(endpoints)} candidate endpoints, {len(secrets)} candidate secrets")
    typer.echo(
        f"found {len(subdomains)} subdomains, {len(parameters)} parameters, "
        f"{len(dom_findings)} DOM findings"
    )
    stats = result.graph_stats
    assert stats is not None
    typer.echo(
        f"knowledge graph: {stats.node_count} nodes, {stats.edge_count} edges, "
        f"{stats.bundle_count} bundles -> {graph_path}"
    )
    typer.echo(
        f"{len(result.hypotheses)} hypotheses generated, evidence bundles written under "
        f"{output / 'evidence'} ({len(evidence_paths)} file(s))"
    )
    if draft_verification_flag:
        typer.echo(
            f"{drafted_count} verification draft(s) written (nothing sent) — run them "
            "yourself, then `bundlebleed verify record <id>` to log the outcome"
        )
    if history_dir is not None:
        if result.scan_diff is None:
            typer.echo(f"history: no prior scan found for this target under {history_dir}")
        else:
            diff = result.scan_diff
            typer.echo(
                f"history: vs. {diff.previous_started_at.isoformat()} — "
                f"+{len(diff.new_endpoints)}/-{len(diff.removed_endpoints)} endpoints, "
                f"+{len(diff.new_secrets)}/-{len(diff.removed_secrets)} secrets, "
                f"+{len(diff.new_subdomains)}/-{len(diff.removed_subdomains)} subdomains"
            )
            if diff.access_control_regressions:
                typer.echo(
                    f"history: {len(diff.access_control_regressions)} endpoint(s) that were "
                    "auth-only last scan are now reachable WITHOUT authentication: "
                    f"{diff.access_control_regressions}"
                )

            if webhook and has_changes(diff):
                sent = asyncio.run(post_webhook(webhook, format_slack_payload(diff, history_key)))
                typer.echo(f"webhook: {'sent' if sent else 'failed to send'} change summary")
        typer.echo(f"snapshot saved to {snapshot_path}")
    typer.echo(f"reports written to {json_path}, {md_path}, and {html_path}")
    typer.echo(
        f"wordlists written to {wordlist_paths['urls'].parent}/ "
        "(urls/endpoints/parameters/subdomains/third-party-hosts.txt)"
    )


@scope_app.command("check")
def scope_check(
    url: Annotated[str, typer.Argument(help="URL or domain to check against scope")],
    target: Annotated[str | None, typer.Option("-t", "--target")] = None,
    target_list: Annotated[Path | None, typer.Option("-tL", "--target-list")] = None,
    config: Annotated[Path | None, typer.Option("--config")] = None,
) -> None:
    """Check whether a URL/domain would be ALLOWed or DENYed, and why."""
    try:
        scope_config = load_scope_config(target, target_list, config)
    except ValueError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from None

    decision = is_in_scope(url, scope_config)
    typer.echo(f"{decision.decision.value}: {decision.reason}")
    if decision.decision.value != "ALLOW":
        raise typer.Exit(code=1)


@scope_app.command("list")
def scope_list(
    target: Annotated[str | None, typer.Option("-t", "--target")] = None,
    target_list: Annotated[Path | None, typer.Option("-tL", "--target-list")] = None,
    config: Annotated[Path | None, typer.Option("--config")] = None,
) -> None:
    """Print the resolved scope: in-scope entries, exclusions, excluded paths."""
    try:
        scope_config = load_scope_config(target, target_list, config)
    except ValueError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from None

    typer.echo("in-scope:")
    for entry in scope_config.in_scope:
        typer.echo(f"  {entry.domain} ({entry.match_type.value})")
    typer.echo("out-of-scope:")
    for excluded in scope_config.out_of_scope:
        typer.echo(f"  {excluded}")
    typer.echo("excluded paths:")
    for path in scope_config.excluded_paths:
        typer.echo(f"  {path}")
    typer.echo(
        f"scan: requests_per_second={scope_config.scan.requests_per_second}, "
        f"delay_between_domains={scope_config.scan.delay_between_domains}"
    )


@verify_app.command("diff")
def verify_diff(
    baseline: Annotated[
        Path, typer.Option("--baseline", help='JSON file: {"status_code": int, "body": str}')
    ],
    test: Annotated[
        Path, typer.Option("--test", help='JSON file: {"status_code": int, "body": str}')
    ],
) -> None:
    """Compare two responses YOU captured after running a drafted
    verification request yourself. This command never sends anything —
    it only compares files you already have."""
    try:
        baseline_data = json.loads(baseline.read_text())
        test_data = json.loads(test.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from None

    result = compare_responses(
        ResponseCapture(status_code=baseline_data["status_code"], body=baseline_data["body"]),
        ResponseCapture(status_code=test_data["status_code"], body=test_data["body"]),
    )

    typer.echo(f"status_match: {result.status_match}")
    typer.echo(f"body_length_delta: {result.body_length_delta:+d}")
    if result.json_keys_added:
        typer.echo(f"json_keys_added: {result.json_keys_added}")
    if result.json_keys_removed:
        typer.echo(f"json_keys_removed: {result.json_keys_removed}")
    if result.sensitive_fields_in_test:
        typer.echo(f"sensitive_fields_in_test: {result.sensitive_fields_in_test}")
    typer.echo(f"suggestion (informational only, not a verdict): {result.suggestion}")


@verify_app.command("record")
def verify_record(
    hypothesis_id: Annotated[str, typer.Argument(help="The hypothesis id to update")],
    outcome: Annotated[str, typer.Option("--outcome", help="confirmed | rejected | inconclusive")],
    output: Annotated[
        Path, typer.Option("-o", "--output", help="The scan's output directory")
    ] = Path("./results"),
    note: Annotated[str | None, typer.Option("--note", help="Optional note")] = None,
) -> None:
    """Record what YOU found after manually running a drafted verification
    request. This is the only way a hypothesis ever becomes
    confirmed/rejected/inconclusive — never automatic."""
    try:
        status = HypothesisStatus(outcome)
    except ValueError:
        typer.echo("error: --outcome must be one of: confirmed, rejected, inconclusive", err=True)
        raise typer.Exit(code=1) from None

    if status not in (
        HypothesisStatus.CONFIRMED,
        HypothesisStatus.REJECTED,
        HypothesisStatus.INCONCLUSIVE,
    ):
        typer.echo("error: --outcome must be one of: confirmed, rejected, inconclusive", err=True)
        raise typer.Exit(code=1)

    try:
        path = record_verification_outcome(output, hypothesis_id, status, note=note)
    except FileNotFoundError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from None

    typer.echo(f"recorded {status.value} for {hypothesis_id} -> {path}")


@ai_app.command("report")
def ai_report(
    hypothesis_id: Annotated[str, typer.Argument(help="The hypothesis id to draft a report for")],
    model: Annotated[
        str,
        typer.Option(
            "--model",
            help="Exact model id to use — CLAUDE.md Invariant 8: models are pinned, "
            "never defaulted.",
        ),
    ],
    provider_name: Annotated[
        str,
        typer.Option(
            "--provider",
            help="Which LLM backend to use: 'anthropic' (default, needs ANTHROPIC_API_KEY), "
            "'ollama' (needs --host, a locally/LAN-hosted model), or 'openrouter' (needs "
            "OPENROUTER_API_KEY; several free-tier models available).",
        ),
    ] = "anthropic",
    host: Annotated[
        str | None,
        typer.Option(
            "--host",
            help="Ollama server URL (e.g. http://172.30.224.1:11434). Required with "
            "--provider ollama — never guessed or defaulted.",
        ),
    ] = None,
    output: Annotated[
        Path, typer.Option("-o", "--output", help="The scan's output directory")
    ] = Path("./results"),
) -> None:
    """Draft a bug bounty report from an existing hypothesis's own
    (already-redacted) evidence. Never submitted anywhere by this tool —
    written as report-draft.md for a human to review and edit."""
    try:
        hypothesis = load_hypothesis(output, hypothesis_id)
    except FileNotFoundError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from None

    provider = _resolve_provider(provider_name, model, host)

    draft, flagged = asyncio.run(draft_report(hypothesis, provider))
    path = write_report_draft(draft, output, hypothesis_id)

    if flagged:
        typer.echo(
            f"WARNING: {len(flagged)} step(s) in the draft read like an exploitation/"
            f"destructive instruction despite the prompt forbidding it — review before "
            f"using: {flagged}",
            err=True,
        )
    typer.echo(f"report draft written to {path}")


@ai_app.command("chains")
def ai_chains(
    model: Annotated[
        str,
        typer.Option(
            "--model",
            help="Exact model id to use — CLAUDE.md Invariant 8: models are pinned, "
            "never defaulted.",
        ),
    ],
    provider_name: Annotated[
        str,
        typer.Option(
            "--provider",
            help="Which LLM backend to use: 'anthropic' (default, needs ANTHROPIC_API_KEY), "
            "'ollama' (needs --host, a locally/LAN-hosted model), or 'openrouter' (needs "
            "OPENROUTER_API_KEY; several free-tier models available).",
        ),
    ] = "anthropic",
    host: Annotated[
        str | None,
        typer.Option(
            "--host",
            help="Ollama server URL (e.g. http://172.30.224.1:11434). Required with "
            "--provider ollama — never guessed or defaulted.",
        ),
    ] = None,
    output: Annotated[
        Path, typer.Option("-o", "--output", help="The scan's output directory")
    ] = Path("./results"),
) -> None:
    """Suggest connections between >= 2 hypotheses from an existing scan's
    scan-result.json. Pure analysis — never a claim that a chain works, was
    tested, or that any hypothesis in it is more than what its own status
    says. Written as attack-chains.md; this tool never acts on a
    suggestion or submits it anywhere."""
    result_path = output / "scan-result.json"
    if not result_path.exists():
        typer.echo(
            f"error: no scan result at {result_path} (run `bundlebleed scan` first)", err=True
        )
        raise typer.Exit(code=1)
    result = ScanResult.model_validate_json(result_path.read_text())

    if len(result.hypotheses) < 2:
        typer.echo(
            f"note: {len(result.hypotheses)} hypothesis(es) in {result_path} — need at "
            "least 2 to suggest a chain; nothing to do"
        )
        raise typer.Exit(code=0)

    provider = _resolve_provider(provider_name, model, host)

    chains, flagged = asyncio.run(suggest_attack_chains(result.hypotheses, provider))
    path = write_attack_chains(chains, output)

    if flagged:
        typer.echo(
            f"WARNING: {len(flagged)} suggested next step(s) read like an exploitation/"
            f"destructive instruction despite the prompt forbidding it — review before "
            f"using: {flagged}",
            err=True,
        )
    typer.echo(f"{len(chains)} attack chain(s) suggested, written to {path}")


def main() -> None:
    _print_banner()
    app()


if __name__ == "__main__":
    main()
