# CLI Reference

Every command BundleBleed ships, in full. Run `bundlebleed <command> --help`
for the live version — this page exists so you can scan the whole surface
at once.

## `bundlebleed scan`

The core command.

```bash
uv run bundlebleed scan -t example.com -o results/
```

### Targeting

| Flag | Default | What it does |
|---|---|---|
| `-t`, `--target` | — | One domain, or comma-separated for several |
| `-tL`, `--target-list` | — | A file, one domain per line; `*.domain.com` wildcard, `!domain.com` exclude |
| `--config` | — | A full `scope.yaml` instead of `-t`/`-tL` — adds rate limiting, the attestation `--active` needs, and session config |
| `-o`, `--output` | `./results` | Output directory |
| `--seed-url` (repeatable) | — | Inject a known URL directly, bypassing the need for archives to have found it — for a fresh/JS-heavy SPA. Still ScopeGuard-checked |
| `--seed-url-file` | — | Same, loaded from a file (`#`-comments and blanks ignored) |

### Collection & download

| Flag | Default | What it does |
|---|---|---|
| `--active` / `--no-active` | off | Enable `katana`. Also needs `active_scan_enabled=true` in app-config **and** `scope.yaml` attestation |
| `--app-config` | — | Path to the app-level `config.yaml` holding `active_scan_enabled` |
| `--download` / `--no-download` | on | Fetch JS/page bodies for deep extraction. Still passive — plain GETs, same as a browser |
| `--concurrency` | `5` | Max concurrent JS file downloads |
| `--check-subdomain-takeover` | off | Resolve each subdomain's CNAME, flag takeover-prone matches. DNS-only, same 3-gate authorization as `--active` |

### Authentication

| Flag | Default | What it does |
|---|---|---|
| `--session` (repeatable) | — | `'name:cookie_string'`. Prefer `--cookie-file` — an inline string is visible in shell history |
| `--cookie-file` | — | Raw header, JSON array, or Netscape `cookies.txt` |

### Runtime capture

| Flag | Default | What it does |
|---|---|---|
| `--runtime-capture` | off | Render pages in headless Chromium, record every real request. Same 3-gate authorization as `--active`, needs `bundlebleed[runtime]` |
| `--runtime-max-pages` | `10` | Cap how many pages get rendered |
| `--runtime-timeout` | `15.0` | Per-page hard timeout, seconds |

### AI (all off by default)

| Flag | Default | What it does |
|---|---|---|
| `--ai` / `--no-ai` | off | Classify endpoints with an LLM. Costs money, sends metadata off-machine (never secrets/raw JS) |
| `--ai-model` | — | Exact model id. **Required** with `--ai` — never defaulted |
| `--ai-provider` | `anthropic` | `anthropic` (needs `ANTHROPIC_API_KEY`), `ollama` (needs `--ai-host`), or `openrouter` (needs `OPENROUTER_API_KEY`) |
| `--ai-host` | — | Ollama server URL. Required with `--ai-provider ollama` |
| `--ai-batch-size` | `20` | Endpoints per LLM call |
| `--ai-dry-run` | off | Show what would be sent, spend nothing |

### Verification drafting

| Flag | Default | What it does |
|---|---|---|
| `--draft-verification` | off | Draft (never send) a baseline/test request pair for IDOR-shaped hypotheses with a numeric id. Same 3-gate authorization as `--active` |

### History & monitoring

| Flag | Default | What it does |
|---|---|---|
| `--history-dir` | — | Diff against the most recent prior scan of the same target (endpoints/secrets/subdomains/access-control regressions) |
| `--webhook` | — | Post a change summary (Slack/Discord-compatible) when `--history-dir` finds a change. Silent otherwise. Not scope-checked — it's your notification channel, not the target |

## `bundlebleed monitor`

A thin loop around `scan --history-dir ... --webhook ...`.

```bash
uv run bundlebleed monitor -t example.com -o results/ --interval-seconds 3600 --webhook <url>
```

| Flag | Default | What it does |
|---|---|---|
| `-t` / `-tL` / `--config` | — | Same targeting as `scan` |
| `-o`, `--output` | `./results` | Output directory |
| `--interval-seconds` | `3600` | Seconds between scans |
| `--webhook` | — | Change-summary destination |
| `--session` / `--cookie-file` | — | Same as `scan` |
| `--once` | off | Run exactly one iteration and exit — confirm the setup before leaving it running |

## `bundlebleed scope check <url>`

Ask ScopeGuard directly whether a URL would be ALLOW or DENY, without
scanning anything.

```bash
uv run bundlebleed scope check https://admin.example.com/api -t example.com
```

## `bundlebleed scope list`

Print the resolved scope rules for a target set.

```bash
uv run bundlebleed scope list --config scope.yaml
```

## `bundlebleed verify diff`

Compare two responses **you** captured by hand after manually running a
drafted test.

```bash
uv run bundlebleed verify diff --baseline before.json --test after.json
```

Flags added/removed JSON keys and sensitive-*looking* field **names**
(email, phone, token, password, ...) — never inspects values.

## `bundlebleed verify record <hypothesis_id>`

The only command that can move a hypothesis past `awaiting_approval`.

```bash
uv run bundlebleed verify record hyp_abc123 --outcome confirmed --note "IDOR confirmed, cross-tenant read" -o results/
```

| Flag | Required | What it does |
|---|---|---|
| `--outcome` | yes | `confirmed`, `rejected`, or `inconclusive` |
| `--note` | no | Free-text note |
| `-o`, `--output` | no (default `./results`) | The scan's output directory |

## `bundlebleed ai report <hypothesis_id>`

Drafts a report from a hypothesis's own already-redacted evidence. Writes
`report-draft.md`. Never submitted anywhere by the tool.

```bash
uv run bundlebleed ai report hyp_abc123 --model claude-opus-5 -o results/
```

| Flag | Required | What it does |
|---|---|---|
| `--model` | yes | Exact model id — pinned, never defaulted |
| `--provider` | no (default `anthropic`) | `anthropic` / `ollama` / `openrouter` |
| `--host` | with `--provider ollama` | Ollama server URL |
| `-o`, `--output` | no | The scan's output directory |

## `bundlebleed ai chains`

Suggests connections across ≥2 hypotheses in an existing
`scan-result.json`. Never claims a chain was tested.

```bash
uv run bundlebleed ai chains --model claude-opus-5 -o results/
```

Same `--model`/`--provider`/`--host`/`-o` flags as `ai report`. Writes
`attack-chains.md`.

---

Full walkthrough of what these produce: [How It Works](02-how-it-works.md).
What every finding type actually is: [Detection Reference](03-detection-reference.md).
