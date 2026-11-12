# Lab 06 — Client-Side DoS via Oversized Logo (Resource Exhaustion)

**Mirrors:** Report 1 — *Client-Side Denial of Service via large-dimension logo upload* (the "Lottapixel" style image)
**Class:** Resource exhaustion / client-side DoS · **Severity:** Low–Medium

## The story

A logo (org branding) with enormous pixel dimensions (the real report used a
`63240 × 63240` PNG) is accepted by the server and then **decoded/rendered
client-side for every member of the organization**. Decoding it pins the CPU and
freezes the browser tab — an org-wide availability disruption. Notably it
reproduced in **Firefox** but not Chrome, which is exactly the kind of
browser-specific nuance that shows up in triage.

## Recon first (BundleBleed)

Hidden branding endpoint mined from the bundle:

```
POST /api-internal/branding/logo
```

## Reproduce (safe, in the lab)

1. Log in as `owner@acme.test`, open the **Branding** tab.
2. Set **Width** and **Height** to a large value, e.g. `30000` each.
3. Click **Render preview**.
4. **Result:** the app allocates a `30000 × 30000` canvas (~3.6 GB of pixels) and
   the tab hangs. In the real bug, the uploader stored this once and *every* org
   member who opened the dashboard was hit.

> Keep it reasonable in the lab (start at 20000) — you can crash your own tab.

## Why it matters

The server treated dimensions as harmless metadata and broadcast the asset to all
tenant users, turning one upload into a tenant-wide DoS. Availability is a
first-class security property.

## The fix

Validate dimensions and total pixel budget **server-side before storing**, cap
rendered size client-side, and reject decompression-bomb-shaped images:

```js
if (width * height > 25_000_000) return res.status(413).json({ error: "logo too large" });
```
