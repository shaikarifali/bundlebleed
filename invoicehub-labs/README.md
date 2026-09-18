# InvoiceHub — Vulnerable Demo Labs

A deliberately vulnerable fake invoicing platform with **six real, already-fixed bugs**
planted in it, built as a companion to the Null-Hyd talk *"The UI Is the Lie: Hunting Bugs
Hidden in JavaScript Bundles."*

Each bug is a rebuild of a real, anonymized finding reported on HackerOne — recreated so
you can reproduce the methodology yourself, not just look at a trophy screenshot. This is
a **separate demo lab app**, not part of the [BundleBleed](https://github.com/shaikarifali/bundlebleed)
tool itself.

## Run it

```bash
npm install
npm start
```

Verify: `curl http://localhost:4000/healthz` should return `{"ok":true}`. Then open
`http://localhost:4000` in a browser.

Or with Docker:

```bash
docker build -t invoicehub .
docker run -p 4000:4000 invoicehub
```

## Accounts

All passwords: `password123`

| Email | Role | MFA | Use for |
|---|---|---|---|
| `owner@acme.test` | owner | on | admin baseline |
| `viewer@acme.test` | viewer | off | privilege-escalation attacker |
| `support@acme.test` | support | off | broken-access-control attacker |
| `owner@globex.test` | owner, other tenant | on | the IDOR **victim** |

Two tenants: `org_ACME0001` (you) and `org_GLOBEX02` (Globex — holds the high-value
customer data).

## Scan it with BundleBleed

InvoiceHub is a fresh SPA with no `gau`/`waybackurls` archive history, so seed the URL
directly:

```bash
uv run bundlebleed scan -t localhost \
  --seed-url http://localhost:4000/ \
  --seed-url http://localhost:4000/app.js \
  -o results/
```

## The six labs

| # | Lab | Class | Hidden endpoint |
|---|---|---|---|
| 01 | Cross-account IDOR | IDOR / BOLA | `/api-internal/v2/invoice-ar/proxy` |
| 02 | Webhook race condition | TOCTOU race | `/api-internal/webhooks` |
| 03 | Support reads merchant profile | Broken access control | `/api-internal/profiles` |
| 04 | MFA not enforced server-side | Improper access control | `/api-internal/v2/memberships/{id}` |
| 05 | Viewer creates & issues invoices | Privilege escalation | `/api-internal/v2/sales-invoices` |
| 06 | Client-side DoS via logo | Resource exhaustion | `/api-internal/branding/logo` |

BundleBleed finds and ranks them. You exploit. That separation is the whole point.

## License

For educational and authorized security-testing use only — this application is
intentionally vulnerable. Do not deploy it publicly reachable.
