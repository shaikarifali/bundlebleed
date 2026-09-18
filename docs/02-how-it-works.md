# How It Works

This page assumes you've run a scan already (see
[Getting Started](01-getting-started.md)) and want to know what actually
happened. Everything here describes real code, not aspiration — file paths
are given throughout so you can go read the source directly.

## The pipeline

A single `bundlebleed scan` invocation runs every stage below, in this
order, inside one process:

```text
TARGET
  │
COLLECT      gau + waybackurls + waymore + paramspider (passive, always) —
             katana (active, only if all 3 authorization gates below hold) —
             or a direct --seed-url / --seed-url-file for a fresh target
  │
SCOPE GUARD  every single URL from COLLECT is checked by ScopeGuard.check()
             before anything downloads it — ALLOW/DENY, logged
  │
EXTRACT      13 endpoint-pattern regexes, 57 secret patterns, DOM sink/source
             co-occurrence, GraphQL operations, CORS headers, mass-assignment
             fields, vulnerable-library banners, subdomain CNAME candidates,
             postMessage / WebSocket listeners — full list in the
             Detection Reference
  │
CONTEXT      auth-only vs anonymous visibility, source-map recovery,
             historical cross-scan matching, optional runtime capture
  │
HYPOTHESIS   score_confidence() combines 7 weighted signals into one
             confidence value; risk_for_confidence() tiers it
  │
OPTIONAL AI  classify / report / chains — never authoritative
  │
OUTPUT       scan-result.{json,md,html}, evidence/<id>/finding.json,
             audit_log.jsonl, wordlists/
```

Every stage after COLLECT operates only on data already pulled down and
scope-checked — nothing downstream issues its own network request.

## Collection: 4 passive sources, 1 active

```python
# bundlebleed/collectors/orchestrator.py
PASSIVE_COLLECTORS = [GauCollector(), WaybackCollector(), WaymoreCollector(), ParamSpiderCollector()]
ACTIVE_COLLECTORS = [KatanaCollector()]
```

The passive four query public archives by domain — no request ever reaches
the target itself at this stage. `katana` is different: it's a real
crawler that sends real requests, so it's gated behind
`active_scan_authorized()`, which requires **all three** of:

1. `active_scan_enabled: true` in a separate app-level config file
2. `--active` on the CLI
3. `authorization_attested: true` in your `scope.yaml`

These are deliberately split across three different places so no single
edit — a config typo, a copy-pasted CLI flag — can silently turn on active
scanning. `--runtime-capture` (below) requires the same three gates.

## The hypothesis / scoring engine

An extracted item only becomes a **Hypothesis** if it first clears a
bug-class gate — see [Detection Reference](03-detection-reference.md#bug-classes)
for the full list. Endpoints specifically need to match an IDOR, broken
function-level auth, or SSRF shape; nothing else even reaches scoring.

Once gated, the confidence score is the sum of seven independently-weighted
booleans (`bundlebleed/hypotheses/scoring.py`), capped at 1.0:

| Signal | Weight | What sets it True |
|---|---|---|
| Discovery pattern match | +0.20 | Always true for anything that reached scoring at all |
| Bug-class rule match | +0.20 | The IDOR/BFLA/SSRF gate itself |
| JS-body-only visibility | +0.15 | Only found by downloading the file body, not the raw collected URL string |
| Authenticated context | +0.20 | Only visible in a bundle reachable with a real session cookie |
| Historical cross-scan match | +0.10 | Also present in a previous scan of the same target |
| Runtime-confirmed | +0.30 | The single highest weight — a real headless-browser page actually requested it |
| AI confidence, capped | +0.10 max | `ai_confidence × 0.10` — the model can nudge a score, never dominate it |

Weights can sum past 1.0 in the best case (0.20+0.20+0.15+0.20+0.10+0.30+0.10
= 1.25); the score is always capped at 1.0.

**Risk tier:** ≥ 0.6 high, ≥ 0.35 medium, else low.

## Runtime capture

Flag: `--runtime-capture`. Renders every collected page in headless
Chromium (via Playwright) and records every real request the page makes —
including redirects, all checked against ScopeGuard and aborted if out of
scope. Observation only: no clicks, no form submission, no keystrokes.

If a session cookie is also supplied (`--session` / `--cookie-file`), each
page is re-rendered per session, so client-side routing gated on auth state
— an admin panel that only lazy-loads its JS chunk for a logged-in user —
renders too. A chunk found only in an authenticated pass is flagged the
same way as an auth-only endpoint. This is what feeds the +0.30
runtime-confirmed signal above.

Requires the optional `playwright` dependency
(`uv sync --extra runtime && uv run playwright install chromium`) and the
same 3-gate authorization as `--active`.

## The AI layer

Fully optional — everything above needs no LLM at all. Three jobs,
provider-agnostic (`--ai-provider anthropic | ollama | openrouter`), every
model id explicitly pinned, never defaulted:

- **Classify** (`scan --ai`): reviews extracted endpoints, flags the
  likely-interesting ones for the AI-confidence scoring term
- **`ai report <hypothesis_id>`**: drafts a bug-report writeup from a
  hypothesis's own already-redacted evidence — writes `report-draft.md`,
  never submitted anywhere by the tool
- **`ai chains`**: looks for connections across ≥2 hypotheses in an
  existing `scan-result.json` — writes `attack-chains.md`

**Hallucination is a hard failure, not a soft one.** Every model verdict
must cite an `evidence_id` that was actually present in its own prompt —
`validate_citations()` raises `UncitedEvidenceError` the instant it isn't.

**Evidence is data, never instruction.** Everything BundleBleed extracts
came from a target you don't control — treated as attacker-controlled
content. `looks_like_injection()` checks every extracted value against
five patterns ("ignore previous instructions," "you are now," "system
prompt," "new instructions," "disregard previous"). A match is flagged as
its own finding, never followed as a command. The model itself only ever
receives `pattern_name / value / source_url` — no secrets, no raw JS body,
no severity value.

## The verification lifecycle

A hypothesis moves through a real state machine, and only one human action
can advance it past the halfway point:

```text
DISCOVERED → HYPOTHESIS → READY_TO_TEST → AWAITING_APPROVAL → TESTED
                                                                  │
                                              CONFIRMED / REJECTED / INCONCLUSIVE
```

`bundlebleed verify record <hypothesis_id> --outcome confirmed|rejected|inconclusive`
is the only thing that can move a hypothesis past `awaiting_approval`.
Nothing automated calls it.

`bundlebleed verify diff --baseline before.json --test after.json` compares
two responses a **human** captured after manually running a drafted test.
It flags added/removed JSON keys and sensitive-*looking* field **names**
(email, phone, token, password, ...) — it never inspects field values, so
it never needs to see real PII to flag that a response likely leaked some.

## Continuous monitoring

`bundlebleed monitor -t target.com -o results/ --interval-seconds 3600 --webhook <url>`
is a thin loop around `scan --history-dir ... --webhook ...`, sleeping
between iterations, silent unless something changed. Every invariant a
normal scan holds applies identically. `--once` runs a single iteration to
confirm the setup before leaving it running unattended.

A plain `scan` can also diff against its own history without looping, via
`--history-dir` (new/removed endpoints, secrets, subdomains, and an
access-control-regression check) and `--webhook` (posts a change summary,
silent on the first scan or when nothing changed).

## The safety model

These are structural properties of the code, not policy statements:

| Guarantee | Enforced by |
|---|---|
| Passive by default | `PASSIVE_COLLECTORS` never sends a probing request; `katana`/`--runtime-capture` need all 3 authorization gates |
| No exploitation | No credential submission, no fuzzing, no brute-forcing anywhere in the codebase; `PROHIBITED_KEYWORDS` flags anything an AI draft says that reads like one anyway |
| One scope choke point | `ScopeGuard.check()` — every collector, downloader, and browser request calls it; every decision is a JSON line in `audit_log.jsonl` |
| Secrets never stored raw | Type + redacted preview + SHA-256 partial hash only — the raw value is never returned from the extractor at all |
| AI has no authority | Citation validation raises hard exceptions on hallucinated references |
| Human fires everything | `ai report`, `ai chains`, `verify record` only ever write files to disk |
| Models are pinned | Every AI command requires an explicit `--model` value — there is no default |

For the exhaustive list of everything the extractors actually detect, see
[03 — Detection Reference](03-detection-reference.md). For internals —
module map, how to add a pattern, how identity/dedup work — see
[04 — Architecture](04-architecture.md).
