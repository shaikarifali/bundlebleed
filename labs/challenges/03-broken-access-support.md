# Lab 03 — Support Role Reads Merchant Profile (Broken Access Control)

**Mirrors:** Report 4 — *Broken Access Control: Support role can access onboarding/profile details via `/api-internal/profiles`*
**Class:** Broken access control / improper authorization · **Severity:** Medium

## The story

The permission matrix (visible on the Team screen) states the **Support** role
has **No access** to Organization details and Onboarding details. The backend
endpoint that returns that data only checks *authentication*, not *role* — so
Support reads full merchant PII: email, phone, VAT id, verification status, KYC
tier, and payment-method configuration.

## Recon first (BundleBleed)

Hidden endpoint mined from the bundle (no UI button points to it for Support):

```
GET /api-internal/profiles?organizationId=<ORG>
```

## Reproduce

1. Log in as `support@acme.test`.
2. The UI shows no "Profile" panel for you — the permission matrix says
   *No access*. Good in theory.
3. Call the endpoint directly:

```bash
curl 'http://localhost:4000/api-internal/profiles?organizationId=org_ACME0001' \
  -H "Cookie: SESSIONID=<your-session>"
```

4. **Result:** the full merchant profile comes back — `vatId`, `phone`,
   `verificationStatus`, `onboarding.kycTier`, `paymentMethods`, etc.

## Why it matters

"Hidden in the UI" is not an access control. Onboarding/KYC data feeds targeted
fraud and social engineering. The role restriction the product *promises* must be
enforced where the decision is actually made — the server.

## The fix

Enforce the same matrix server-side:

```js
if (PERMISSION_MATRIX[req.user.role].profile === "no-access")
  return res.status(403).json({ error: "forbidden" });
```
