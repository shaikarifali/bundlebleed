# InvoiceHub — BundleBleed Demo Labs

A deliberately vulnerable **invoicing-platform clone** built for the BundleBleed
talk at Null-Hyd. Every bug here mirrors a **real, already-fixed finding** from a
live bug-bounty program — fully anonymised. The target domain, company name,
tenant/organization IDs, session cookies and CSRF tokens have all been replaced
with fictional `redacted.com` / `org_ACME0001` style values.

> ⚠ **Authorized learning only.** Run this locally or in a lab you control.
> Do **not** expose it to the public internet. It ships intentional
> vulnerabilities and zero real data.

> 📖 **New here? Start with [SETUP.md](SETUP.md)** — the full step-by-step guide:
> prerequisites, running the target, installing BundleBleed, every command, and
> the exploit flow for all six labs.

---

## The workflow this lab teaches

```
BundleBleed ──► find hidden /api-internal/* endpoints in the JS bundle
                     │
                     ▼
You (human) ──► reason about which endpoints look juicy
                     │
                     ▼
Manual test ──► reproduce & exploit each bug by hand (Burp / curl / console)
```

BundleBleed **finds and triages**. *You* exploit. That separation is the whole
point — it is a recon + triage assistant, never an auto-exploiter.

---

## Quick start

**Option A — Docker (recommended):**

```bash
cd labs
docker compose up --build
# open http://localhost:4000
```

**Option B — Node directly:**

```bash
cd labs/invoicehub
npm install
npm start
# open http://localhost:4000
```

## Demo accounts (password: `password123`)

| Email | Role | MFA | Purpose |
|---|---|---|---|
| `owner@acme.test` | owner | on | admin baseline |
| `viewer@acme.test` | viewer | off | privilege-escalation attacker |
| `support@acme.test` | support | off | broken-access-control attacker |
| `owner@globex.test` | owner (other tenant) | on | the IDOR **victim** |

Two tenants exist: `org_ACME0001` (Acme) and `org_GLOBEX02` (Globex — the victim
holding the "SECRET" high-value customers).

---

## The six labs

| # | Lab | Class | Mirrors report | Hidden endpoint |
|---|---|---|---|---|
| 01 | [Cross-account IDOR](challenges/01-idor-cross-account.md) | IDOR / broken object-level auth | Report 3 | `/api-internal/v2/invoice-ar/proxy` |
| 02 | [Webhook race condition](challenges/02-race-condition-webhooks.md) | TOCTOU race | Report 2 | `/api-internal/webhooks` |
| 03 | [Support reads merchant profile](challenges/03-broken-access-support.md) | Broken access control | Report 4 | `/api-internal/profiles` |
| 04 | [MFA not enforced server-side](challenges/04-mfa-not-enforced.md) | Improper access control | Report 5 | `/api-internal/v2/memberships/{id}` |
| 05 | [Viewer creates invoices](challenges/05-viewer-privilege-escalation.md) | Privilege escalation | Report 6 | `/api-internal/v2/sales-invoices` |
| 06 | [Client-side DoS via logo](challenges/06-client-side-dos.md) | Resource exhaustion | Report 1 | `/api-internal/branding/logo` |

Full walkthrough of running BundleBleed against this lab:
[bundlebleed-walkthrough.md](bundlebleed-walkthrough.md).

Stuck? Solutions in [challenges/solutions.md](challenges/solutions.md).

---

## Hosting this on GitHub (so anyone can try it later)

1. Create a new public repo, e.g. `invoicehub-bundlebleed-labs`.
2. Copy the contents of this `labs/` folder into it.
3. Commit and push:

```bash
git init && git add . && git commit -m "InvoiceHub demo labs"
git branch -M main
git remote add origin https://github.com/<you>/invoicehub-bundlebleed-labs.git
git push -u origin main
```

4. Add the "Quick start" block to the top of the repo README so visitors can run
   it in one command.
5. (Optional) Add a GitHub Codespaces `devcontainer` so people can launch it in
   the browser with zero local setup.
