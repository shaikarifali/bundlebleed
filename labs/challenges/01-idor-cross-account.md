# Lab 01 — Cross-Account IDOR (Broken Object-Level Authorization)

**Mirrors:** Report 3 — *Horizontal Privilege Escalation → Cross-Account Information Disclosure*
**Class:** IDOR / BOLA · **Severity:** High

## The story

A low-privileged **Viewer** on one tenant can read another tenant's customer
data — IBANs, emails, spend — just by changing an `organizationId` value. The
platform enforces tenant isolation in the **UI**, but the backend proxy trusts
whatever org you send it.

## Recon first (BundleBleed)

The endpoint is **never linked** from any button. You only learn it exists by
mining the JS bundle:

```
/api-internal/v2/invoice-ar/proxy?organizationId=<ORG>&path=customers
```

BundleBleed extracts it from `public/app.js` as a `fetch()` candidate endpoint
with a security-interesting parameter (`organizationId`).

## Reproduce

1. Log in as `viewer@acme.test` (belongs to `org_ACME0001`).
2. Open the **Customers** tab — it loads *your* org's customers via the hidden proxy.
3. Now tamper with the org id. In the browser console (or Burp), replay:

```bash
curl 'http://localhost:4000/api-internal/v2/invoice-ar/proxy?organizationId=org_GLOBEX02&path=customers' \
  -H "Cookie: SESSIONID=<your-session-cookie>"
```

4. **Result:** you get Globex's customers (`SECRET Whale Corp`, IBANs, €4.2M
   spend) — a tenant you have no membership in.

## Why it matters

Tenant isolation is the single most important guarantee of a multi-tenant SaaS.
One missing `if (req.user.orgId !== orgId)` collapses it for every customer.

## The fix

Authorize the **object**, not just the session:

```js
if (req.user.orgId !== orgId) return res.status(403).json({ error: "forbidden" });
```
