<p align="center">
  <img src="assets/logo.png" alt="BundleBleed logo" width="260">
</p>

# BundleBleed

**Scope-gated JavaScript reconnaissance for authorized bug bounty testing and pentesting.**

BundleBleed collects a target's client-side JavaScript and server-rendered
pages, extracts candidate API endpoints, secrets, subdomains, parameters,
and DOM-XSS-shaped sink/source pairs, then turns those raw findings into
scored, explainable hypotheses — so you spend your limited engagement time
on the handful of things actually worth a manual look, not a flat dump of
every string that resembled a URL.

Everything above works with **zero LLM, zero API key, and zero third-party
account** — an optional AI layer (Anthropic, a self-hosted Ollama model, or
OpenRouter's free tier — your choice, never hardcoded to one vendor) can
additionally classify endpoints, draft a report from a hypothesis, or
suggest connections between findings, but the core pipeline never depends
on it.

## Why this one

Most JS-recon tools stop at "here are the endpoints/secrets I found."
BundleBleed's actual job is triage: every finding is scored on multiple
independent signals (is it only visible after login, was it actually
requested at runtime, does it match a known vulnerability shape, has it
shown up in a previous scan of the same target) before it's presented to
you — so a hunter with a two-day window can see the highest-signal leads
first instead of scrolling a wall of strings.

It's also built with a genuinely enforced safety model, not just a
disclaimer: a single `ScopeGuard` choke point that every outbound request
passes through, active scanning gated behind three independent
confirmations, and a verification layer that drafts a test for a human to
run but **never sends anything itself.**

## Features

**Collection & scope**
- Scope from `-t domain.com`, `-tL scope.txt` (many domains, wildcards,
  exclusions), or a full `scope.yaml` (rate limiting, authorization
  attestation, sessions)
- Passive collection via `gau`/`waybackurls`; active crawling via `katana`,
  gated behind an explicit config flag *and* CLI flag *and* a signed
  authorization attestation — all three, every time
- `--seed-url`/`--seed-url-file` to inject known URLs directly — essential
  for a freshly provisioned or JS-heavy SPA target with no archive history
- Every single URL, from any source, is re-validated through `ScopeGuard`
  before it's ever used, with an audit-log row per decision

**Extraction**
- Candidate API endpoints: `/api/...` paths, Express/OpenAPI route params,
  `fetch()`/`axios()`/`$.ajax()`/`$.get()`/`$.post()`, bare `axios(...)`
  and config-object shorthand, raw `XMLHttpRequest.open()`,
  `navigator.sendBeacon()`, GraphQL, WebSocket — plus plain server-rendered
  `<a href>` links and `<form action>` targets that JS-only patterns miss
- 31 secret patterns (AWS/GCP/Azure keys, Stripe, Slack, Twilio, SendGrid,
  Discord, Square, Shopify, PayPal/Braintree, private key blocks, JWTs,
  generic Bearer tokens, ...) — always redacted (type + preview + partial
  hash only, never plaintext)
- Higher-severity shapes chosen from real disclosed HackerOne/Bugcrowd
  reports: SSRF-shaped parameters, prototype-pollution-prone deep-merge
  calls, JWT `alg:none` (every JWT's header is decoded to check),
  CORS misconfiguration (`Allow-Origin: *` + `Allow-Credentials: true`),
  open/misconfigured Firebase-style databases, third-party script/supply-
  chain surface
- In-domain subdomains, security-interesting parameters (from both JS
  declarations and URL query strings), DOM-XSS sink/source co-occurrence
- Source maps are followed and, when a map embeds `sourcesContent`, the
  original unminified source is recovered and analyzed too — at zero
  additional network cost, since the map was already being fetched

**Hypothesis engine**
- Flat findings become scored `Hypothesis` objects only when they match a
  known vulnerability shape — an ordinary finding with no signal isn't
  hypothesis-worthy on its own
- Multi-factor confidence: static pattern match, JS-body-only visibility,
  rule match, authenticated-context, historical cross-scan match,
  runtime-confirmed evidence, and capped AI confidence, combined into one
  score and risk tier
- Optional authenticated crawling (pre-obtained cookie — no login
  automation) and headless-browser runtime capture (every request
  individually scope-checked before it's allowed to fire) feed real
  signal into the same scoring

**Verification — always human-fired**
- For IDOR hypotheses with a concrete numeric id, drafts exactly one test
  variant as `.http`/`curl` artifacts — a cookie, if any, is always a
  placeholder, never a real value
- **This tool never sends the drafted request itself.** A human runs it and
  records the outcome — the only way a hypothesis's status ever changes

**AI layer (fully optional)**
- `--ai` classifies endpoints with a versioned prompt; every claim must
  cite an id that was actually in the prompt, or it's a hard failure, not
  a warning
- `ai report` drafts a report from a hypothesis's own already-redacted
  evidence; a keyword check flags any step that reads like an
  exploitation instruction despite the prompt forbidding it
- `ai chains` suggests connections between two or more hypotheses from the
  same scan, with the same citation-validation discipline
- Works against Anthropic, a self-hosted Ollama model, or OpenRouter
  (several genuinely free-tier models) — pick one, or use none of it

**Reporting**
- JSON, Markdown, and a self-contained HTML dashboard (no CDN, works via
  `file://`, sortable/filterable tables, light/dark aware)
- Plain-text wordlists (`urls`/`endpoints`/`parameters`/`subdomains`/
  `third-party-hosts`) for piping straight into `ffuf`, `httpx`, Burp
  Intruder, `nuclei`
- Optional scan history + diffing across runs (flags an endpoint moving
  from authenticated-only to public, among other regressions), with
  webhook alerts that stay silent unless something actually changed

## Safety model

These are structural constraints, not a policy document:

| Guarantee | How it's enforced |
|---|---|
| No exploitation, ever | No credential submission, no fuzzing, no brute-forcing, no writes to a target — not a configuration option, not present in the code |
| Every outbound request is scope-checked | `ScopeGuard` is the single choke point; every collector, downloader, and browser request routes through it, with an audit-log row per decision |
| Passive by default | Active scanning requires an explicit config flag **and** CLI flag **and** a signed attestation in `scope.yaml` — all three |
| The AI has no authority | It classifies and drafts; it never decides scope, never sends a request, never confirms or closes a finding. Every claim must cite real evidence — a hallucinated citation is a hard failure |
| Evidence is data, never instruction | Content scanned from a target is attacker-controlled; anything in it that looks like an instruction is reported as a finding, never obeyed |
| A human approves everything outbound | Verification requests, reports, and alerts all draft; only a human ever sends |
| Secrets are redacted at ingest | Type + preview + partial hash only — a live credential never touches a log, report, or evidence file in plaintext |

## Installation

Requires Python 3.12+ and [`uv`](https://docs.astral.sh/uv/).

```bash
git clone <this-repo>
cd bundlebleed
uv sync
```

Optional, for headless-browser runtime capture:

```bash
uv sync --extra runtime
uv run playwright install chromium
```

## Quick start

```bash
# Single domain
uv run bundlebleed scan -t example.com -o results/

# Multiple domains, comma-separated
uv run bundlebleed scan -t example.com,api.example.com -o results/

# Multiple domains from a file (wildcards with '*.', exclusions with '!')
uv run bundlebleed scan -tL examples/scope-multi-domain.txt -o results/

# Full control via scope.yaml (rate limiting, authorization attestation, sessions)
uv run bundlebleed scan --config scope.yaml -o results/

# Fresh/JS-heavy target with no gau/waybackurls archive history
uv run bundlebleed scan -t example.com --seed-url https://example.com/ -o results/
```

Every command and subcommand supports `-h`/`--help`
(`bundlebleed -h`, `bundlebleed scan -h`, `bundlebleed ai report -h`, ...) —
`bundlebleed scan -h` in particular includes worked examples for every
scenario above.

Output lands in the directory you pass to `-o`:

```
results/
├── scan-result.json       # full structured result
├── scan-result.md         # human-readable summary
├── scan-result.html       # self-contained dashboard (open in a browser)
├── wordlists/              # plain .txt lists for other tools
├── evidence/<id>/          # one folder per hypothesis
└── audit_log.jsonl         # every ScopeGuard decision
```

### Optional AI-assisted analysis

```bash
# Anthropic
export ANTHROPIC_API_KEY=sk-ant-...
uv run bundlebleed scan -t example.com -o results/ --ai --ai-model claude-opus-5

# Self-hosted Ollama
uv run bundlebleed scan -t example.com -o results/ \
  --ai --ai-provider ollama --ai-model llama3 --ai-host http://localhost:11434

# OpenRouter (free account, several genuinely free-tier models)
export OPENROUTER_API_KEY=sk-or-...
uv run bundlebleed scan -t example.com -o results/ \
  --ai --ai-provider openrouter --ai-model meta-llama/llama-3.1-8b-instruct:free

# Draft a report from a hypothesis already in the evidence store
uv run bundlebleed ai report <hypothesis-id> --model claude-opus-5 -o results/

# Suggest connections between a scan's hypotheses
uv run bundlebleed ai chains -o results/ --model claude-opus-5
```

### Manual verification workflow

```bash
# Requires --active + active_scan_enabled (app config) + scope.yaml attestation
uv run bundlebleed scan --config scope.yaml -o results/ --active --draft-verification

# ...then, after you run the drafted script yourself and capture both responses:
uv run bundlebleed verify diff --baseline resp-baseline.json --test resp-test.json
uv run bundlebleed verify record <hypothesis-id> --outcome confirmed -o results/
```

## What it deliberately doesn't do

- Send a verification or exploitation request itself — always human-fired,
  by design
- Automate a login flow — only pre-obtained session cookies are supported
- Decide scope, submit findings, or act on an AI suggestion autonomously
- Fuzz, brute-force, or write (POST/PUT/DELETE) to a target under any flag

## Development

```bash
uv sync
uv run ruff check .
uv run ruff format --check .
uv run mypy --strict bundlebleed
uv run pytest
```

No live network calls are made anywhere in the test suite — every HTTP
call is mocked, every external tool invocation is faked, and
runtime-instrumentation tests drive a real headless browser against inert
`data:` URLs only.

## Legal

This tool is intended for **authorized security testing only.** Always
obtain written permission before testing any target — enroll in the
program's bug bounty platform, or get explicit written authorization
outside one. `ScopeGuard` enforces whatever scope you configure; it cannot
know if that configuration itself is authorized. Unauthorized access to
computer systems is illegal. The authors are not responsible for misuse of
this tool.

## License

MIT — see [LICENSE](LICENSE).
