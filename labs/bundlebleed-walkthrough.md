# Running BundleBleed Against the InvoiceHub Lab

This is the live-demo script for the talk: point BundleBleed at the lab, let it
mine the JS bundle, and watch the hidden `/api-internal/*` endpoints (and a
leaked test key) fall out — then pivot to manual exploitation.

## 0. Start the lab

```bash
cd labs && docker compose up --build   # http://localhost:4000
```

## 1. Seed BundleBleed with the app URL

The lab is a fresh SPA with no `gau`/`waybackurls` archive history, so inject the
URL directly (exactly the "fresh / JS-heavy target" flow from the README):

```bash
uv run bundlebleed scan -t localhost \
  --seed-url http://localhost:4000/ \
  --seed-url http://localhost:4000/app.js \
  -o results/ --runtime-capture
```

> `--runtime-capture` renders the page in headless Chromium and records the real
> requests the SPA fires — so the endpoints that only appear at runtime get
> captured alongside the ones extracted statically from `app.js`.

## 2. What BundleBleed should surface

**Candidate endpoints** (from `fetch()` calls + the `API = {...}` map in the
bundle) — including the ones with **no UI button**:

- `/api-internal/v2/invoice-ar/proxy` ← Lab 01 (IDOR)
- `/api-internal/webhooks` ← Lab 02 (race)
- `/api-internal/profiles` ← Lab 03 (broken access)
- `/api-internal/v2/memberships/{id}` ← Lab 04 (MFA)
- `/api-internal/v2/sales-invoices` ← Lab 05 (priv-esc)
- `/api-internal/branding/logo` ← Lab 06 (DoS)
- `/api-internal/admin/v3/export-all-tenants` ← recon bait (dead ref)
- `/api/v1/legacy/billing/run-settlement` ← recon bait (dead ref)

**Security-interesting parameters:** `organizationId`, `path`, `testmode`.

**Secrets (redacted at ingest):** a PostHog-style key and a `sk_test_…`
Stripe-shaped test token embedded in `ANALYTICS_CONFIG`. Both are fake — they
demonstrate the 57-pattern secret scanner and its redaction guarantee (type +
preview + partial hash only, never plaintext).

## 3. Read the triage output

```bash
open results/scan-result.html      # sortable/filterable dashboard
cat results/scan-result.md         # human-readable summary
ls results/wordlists/              # endpoints.txt, parameters.txt, ...
```

Feed the endpoint wordlist straight into your manual tooling:

```bash
ffuf -w results/wordlists/endpoints.txt -u http://localhost:4000/FUZZ
```

## 4. (Optional) AI flavour

Classify the extracted endpoints and rank the interesting ones — every claim must
cite a real evidence id from the scan or it's rejected:

```bash
uv run bundlebleed scan -t localhost --seed-url http://localhost:4000/app.js \
  -o results/ --ai --ai-provider openrouter \
  --ai-model meta-llama/llama-3.1-8b-instruct:free
```

Then draft a report from a scored hypothesis (writes `report-draft.md` from
already-redacted evidence — never submits anything):

```bash
uv run bundlebleed ai report <hypothesis-id> -o results/ --model claude-opus-5
```

## 5. Pivot to manual exploitation

Open `challenges/0X-*.md` and exploit each endpoint by hand. **BundleBleed found
and ranked them; you land the bug.** That is the demo's punchline.
