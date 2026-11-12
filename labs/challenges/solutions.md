# Solutions & Cheat-Sheet

Spoilers. Try the challenges first.

| # | Endpoint | The missing check | One-line exploit |
|---|---|---|---|
| 01 | `GET /api-internal/v2/invoice-ar/proxy?organizationId=&path=customers` | `req.user.orgId !== orgId` | change `organizationId` to `org_GLOBEX02` |
| 02 | `POST /api-internal/webhooks` | atomic check-and-insert / lock | 20 concurrent identical POSTs |
| 03 | `GET /api-internal/profiles?organizationId=` | role != `no-access` for profile | call it as `support@acme.test` |
| 04 | `DELETE /api-internal/v2/memberships/{id}` | `req.user.mfaEnabled` | DELETE with a valid CSRF, MFA off |
| 05 | `POST /api-internal/v2/sales-invoices` | role in `{owner,finance}` | POST as `viewer@acme.test` |
| 06 | `POST /api-internal/branding/logo` | pixel-budget cap | dimensions `30000 × 30000` |

## Getting your session + CSRF quickly

```js
// in the browser console after logging in:
const me = await (await fetch('/api-internal/auth/me', {credentials:'include'})).json();
console.log(me.csrfToken); // X-Csrf-Token value
document.cookie;           // SESSIONID=...
```

## Tenant / id reference

- Attacker tenant: `org_ACME0001` (Acme Retail BV)
- Victim tenant: `org_GLOBEX02` (Globex — holds the "SECRET" high-value customers)
- Membership ids: `mem_alice`, `mem_vince`, `mem_sam`, `mem_gary`

## The teaching point

Five of six bugs are the **same root cause**: authorization decided in the client
(hidden button, hidden tab, org id chosen by the UI) instead of the server. The
JS bundle *tells you* every endpoint the client can reach — BundleBleed just reads
it for you, at scale, and ranks the ones worth your manual time.
