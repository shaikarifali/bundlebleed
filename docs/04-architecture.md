# Architecture & Extending

For people building on top of BundleBleed, adding detection coverage, or
contributing. Assumes you've read [How It Works](02-how-it-works.md).

## Module map

*(Diagram: [Architecture Diagrams § 2](07-architecture-diagrams.md#2-module-architecture)
for this same map as a dependency graph.)*

```text
bundlebleed/
├── cli.py                 Typer app; scan/monitor/scope/verify/ai commands
├── config.py               App-level config.yaml (active_scan_enabled, ...)
├── models.py                Pydantic models: Endpoint, Secret, ScanResult, ...
├── identity.py              Deterministic id hashing (stable_id, endpoint_id)
├── ratelimit.py             BundleBleed's own outbound-request throttling
├── logging.py                structlog JSON config
│
├── collectors/              URL sources — the Collector protocol
│   ├── base.py                 run_subprocess_lines / _capturing_file, Collector
│   ├── gau.py, wayback.py, waymore.py, paramspider.py   passive
│   ├── katana.py                                          active (3-gate)
│   └── orchestrator.py       PASSIVE_COLLECTORS / ACTIVE_COLLECTORS, collect_all()
│
├── scope/                   ScopeGuard — the one choke point
│   ├── guard.py                 check() / allowed() / filter_allowed()
│   ├── validator.py             in-scope matching logic
│   ├── parser.py                 scope.yaml loading
│   └── models.py
│
├── downloader/               Fetching JS/pages, always through ScopeGuard
│   ├── http_client.py            GuardedHttpClient
│   ├── fetcher.py                 fetch_js_files / fetch_page_files
│   └── sourcemap.py                source-map recovery
│
├── auth/                     Session-cookie based authenticated crawling
│   ├── cookies.py, parser.py, models.py
│   └── crawler.py                fetch_authenticated_script_urls
│
├── processors/               beautify(), framework_detect()
│
├── extractors/                Pure text-in, models-out — no network
│   ├── patterns.py               YAML pattern loaders (see below)
│   ├── endpoints.py               extract_endpoints, deduplicate_endpoints
│   ├── secrets.py                  extract_secrets (+ redaction, alg:none)
│   ├── html_links.py                <a href> / <form> extraction
│   ├── dom_analysis.py               sink/source co-occurrence
│   ├── cors.py, mass_assignment.py, graphql.py, messaging.py
│   ├── dependencies.py               vulnerable-library fingerprinting
│   ├── subdomains.py, parameters.py
│
├── data/                      The actual pattern definitions (YAML)
│   ├── endpoint_patterns.yaml, secret_patterns.yaml
│   ├── dom_sinks.yaml, dom_sources.yaml
│   ├── vulnerable_libraries.yaml, framework_signatures.yaml
│   └── parameter_keywords.yaml
│
├── runtime/                   Headless-browser capture (--runtime-capture)
│   ├── browser.py                 capture_runtime / capture_page
│   └── interceptor.py               per-request ScopeGuard enforcement
│
├── knowledge/                 Cross-referencing everything into one graph
│   ├── graph.py, schema.py (endpoint_schema_discrepancy), export.py
│
├── hypotheses/                 The triage core
│   ├── scoring.py                  ConfidenceFactors, score_confidence()
│   ├── engine.py                    generate_hypotheses() — the big one
│   └── models.py                     Hypothesis, HypothesisStatus
│
├── verification/               Human-gated test drafting, never sending
│   ├── drafter.py, differential.py (verify diff), artifacts.py
│   └── subdomain_takeover.py          CNAME-suffix checking
│
├── evidence/                    Per-hypothesis JSON bundles, report drafts
│
├── ai/                          Fully optional, structurally powerless
│   ├── providers/                    anthropic.py, ollama.py, openrouter.py
│   ├── tasks/                          endpoint_intel, report_writer, attack_chains
│   ├── evidence.py                      build_evidence_items, looks_like_injection
│   ├── validator.py                      validate_citations (hard failure on hallucination)
│   ├── safety.py                          PROHIBITED_KEYWORDS
│   └── prompt_loader.py, schema.py
│
├── history/                    Cross-scan diffing (--history-dir, monitor)
│   ├── snapshots.py, diff.py, models.py
│
├── monitoring/                  Webhook change notifications
│   └── formatter.py, webhook.py
│
└── reporters/                   Output writers
    ├── json_report.py, markdown_report.py, html_dashboard.py
    └── wordlists.py
```

## Adding a detection pattern — no Python required

Endpoint patterns, secret patterns, DOM sinks/sources, and vulnerable
library fingerprints are **all YAML-driven**. Adding a new one to any of
these categories is a data change, not a code change:

```yaml
# bundlebleed/data/secret_patterns.yaml
- name: my_new_service_token
  regex: 'mysvc_[A-Za-z0-9]{32}'
  severity: high
```

That's the entire addition — `load_secret_patterns()`
(`extractors/patterns.py`) picks it up automatically, cached via
`@lru_cache`. The same applies to `endpoint_patterns.yaml`,
`dom_sinks.yaml`, `dom_sources.yaml`, and `vulnerable_libraries.yaml`
(which additionally needs `vulnerable_below`, `cve`, and `description`).

**If you want the new pattern to also produce a named bug class** (rather
than the generic "Hardcoded Credential Exposure" bucket for secrets, or no
hypothesis at all for endpoints), that part *does* need a Python change —
add a branch to the relevant `if`/`elif` chain in
`bundlebleed/hypotheses/engine.py`. Every existing branch there is a
worked example of the pattern: match on `secret.secret_type` or a
sink/pattern name, set `bug_classes` and a `proposed_test` string, done.

**Endpoint patterns can also capture an HTTP method**, if the matched text
itself names it unambiguously — see `axios_call`'s `method_group: 1` in
`endpoint_patterns.yaml` for the pattern, and
[03 — Detection Reference](03-detection-reference.md#endpoint-discovery--13-named-patterns)
for which existing patterns do this. Never add a static `method:` unless
it's genuinely fixed regardless of the match (like `send_beacon`'s POST).

## Key internals

**Identity & dedup** (`identity.py`, `extractors/endpoints.py`):
`stable_id(*parts)` is a deterministic SHA-256-based id from a tuple of
strings — same inputs always produce the same id, which is what makes
idempotency and AI-verdict cross-referencing work. `endpoint_id()` hashes
`(pattern_name, value, source_url)`. Because `deduplicate_endpoints()`
keeps the *first-seen* file as the primary `source_url` when merging
duplicates across files, this id stays stable across reruns as long as
file processing order is stable.

**The hypothesis engine's gate-then-score shape** (`hypotheses/engine.py`):
nothing gets scored just because a regex matched. Endpoints need a
bug-class rule match (IDOR/BFLA/SSRF shape) to even become a hypothesis;
`if not rule_match: continue` is the literal gate. Secrets, DOM findings,
and GraphQL mutations always generate a hypothesis (they're inherently a
finding), but *which* bug class and `proposed_test` they get is a big
`elif` chain keyed on the specific pattern name.

**Evidence chains are additive, not overwritten**: every signal that
contributed to a hypothesis appends a plain-English line to
`evidence_chain` — "Only visible after downloading the JS body," "Also
referenced from N other file(s)," etc. When you add a new scoring signal
or bug class, add a matching evidence-chain line; it's what makes a
hypothesis's score explainable in the report rather than a bare number.

**The `Collector` protocol** (`collectors/base.py`): `async def
collect(self, domain: str, seed_urls: list[str]) -> list[str]`. Two
subprocess-wrapping helpers exist — `run_subprocess_lines` for a tool that
prints to stdout (gau, waybackurls, katana), and
`run_subprocess_capturing_file` for one that writes to a file instead
(waymore, ParamSpider — give it a throwaway temp path, it reads the file
back). Both treat a missing binary or non-zero exit as zero results with a
logged warning, never a scan-aborting error — a broken/missing tool should
degrade the scan's coverage, not crash it.

## Engineering standards

- Python 3.12, `uv` for dependency management
- `ruff check` + `ruff format --check` + `mypy --strict` all pass before
  any change is considered done
- Pydantic v2 for every model that crosses a boundary (config, CLI I/O, AI
  I/O)
- Async by default in orchestration/I/O paths; sync is fine for pure logic
- Structured logging via `structlog`, one `scan_run_id` correlating every
  log line in a run
- **No live network calls in the test suite, ever.** Parser/extractor
  tests use inline fixtures or golden files under `tests/fixtures/`.
  Collector tests monkeypatch the subprocess-wrapping helper and assert on
  the constructed CLI args (see `tests/test_collectors_katana.py`,
  `tests/test_collectors_waymore.py` for the pattern)
- Idempotency is a first-class property: running the same scan twice must
  produce zero *new* change events (see `tests/test_idempotency.py`) — if
  it doesn't, some id isn't as stable as it should be

## Contributing

1. `uv sync` (dev dependencies included)
2. Make your change — YAML pattern, extractor, or engine logic
3. Add a test. Parsers get a should-match/should-not-match pair; new
   engine branches get a `test_hypotheses_engine.py` case following the
   existing `test_<condition>_generates_<bug_class>_hypothesis` naming
4. `uv run pytest -q && uv run ruff check . && uv run ruff format --check . && uv run mypy bundlebleed/`
   — all four clean before you open a PR
5. If you touched an invariant (added an active-scan-adjacent capability,
   changed what reaches an AI prompt, changed a redaction rule), say so
   explicitly in the PR description — those changes get read more
   carefully than a new secret pattern

See [05 — CLI Reference](05-cli-reference.md) for the full flag surface, or
[06 — FAQ](06-faq.md) for questions that come up often.
