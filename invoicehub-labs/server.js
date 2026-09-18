// ============================================================================
// InvoiceHub — Deliberately Vulnerable Invoicing Platform (Demo Lab)
// ----------------------------------------------------------------------------
// Built for the BundleBleed talk @ Null-Hyd.
// Every vulnerability here mirrors a REAL, already-fixed finding, fully
// anonymised: the target domain, org IDs, tokens and company name have all
// been replaced with fictional "redacted" values.
//
// ⚠ FOR AUTHORIZED LEARNING ONLY. Run it locally / in a lab you control.
// Do NOT deploy this to the public internet.
// ============================================================================
import express from "express";
import cookieParser from "cookie-parser";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 4000;

app.use(express.json({ limit: "2mb" }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

// ---------------------------------------------------------------------------
// Seed data — two tenants (organizations), users with different roles.
// This is the whole "database". Everything is in memory and resets on restart.
// ---------------------------------------------------------------------------
const db = {
  organizations: {
    org_ACME0001: { id: "org_ACME0001", name: "Acme Retail BV" },
    org_GLOBEX02: { id: "org_GLOBEX02", name: "Globex Trading Ltd" },
  },
  // password is "password123" for every demo user (this is a lab!)
  users: {
    "owner@acme.test": { id: "usr_owner", name: "Alice Owner", role: "owner", orgId: "org_ACME0001", mfaEnabled: true },
    "viewer@acme.test": { id: "usr_viewer", name: "Vince Viewer", role: "viewer", orgId: "org_ACME0001", mfaEnabled: false },
    "support@acme.test": { id: "usr_support", name: "Sam Support", role: "support", orgId: "org_ACME0001", mfaEnabled: false },
    "owner@globex.test": { id: "usr_globex", name: "Gary Globex", role: "owner", orgId: "org_GLOBEX02", mfaEnabled: true },
  },
  memberships: {
    mem_alice: { id: "mem_alice", userId: "usr_owner", orgId: "org_ACME0001", role: "owner" },
    mem_vince: { id: "mem_vince", userId: "usr_viewer", orgId: "org_ACME0001", role: "viewer" },
    mem_sam: { id: "mem_sam", userId: "usr_support", orgId: "org_ACME0001", role: "support" },
    mem_gary: { id: "mem_gary", userId: "usr_globex", orgId: "org_GLOBEX02", role: "owner" },
  },
  // Sensitive per-org customer records — the crown jewels for the IDOR lab.
  customers: {
    org_ACME0001: [
      { id: "cus_a1", name: "John Buyer", email: "john@buyer.test", iban: "NL91ABNA0417164300", spend: 12450 },
      { id: "cus_a2", name: "Mary Client", email: "mary@client.test", iban: "NL39RABO0300065264", spend: 8800 },
    ],
    org_GLOBEX02: [
      { id: "cus_g1", name: "SECRET Whale Corp", email: "cfo@whale.test", iban: "DE89370400440532013000", spend: 4200000 },
      { id: "cus_g2", name: "SECRET Nova PLC", email: "ap@nova.test", iban: "GB29NWBK60161331926819", spend: 990000 },
    ],
  },
  // Full merchant profile — the "No access" data the Support role must not read.
  profiles: {
    org_ACME0001: {
      organizationId: "org_ACME0001", legalName: "Acme Retail BV", email: "finance@acme.test",
      phone: "+31-20-1112233", vatId: "NL8000.11.222.B01", verificationStatus: "verified",
      businessCategory: "ecommerce", onboarding: { kycTier: 3, riskScore: "low" },
      paymentMethods: { ideal: "active", creditcard: "active", paypal: "pending-review" },
    },
    org_GLOBEX02: {
      organizationId: "org_GLOBEX02", legalName: "Globex Trading Ltd", email: "ops@globex.test",
      phone: "+44-20-7654321", vatId: "GB123456789", verificationStatus: "under-review",
      businessCategory: "crypto-adjacent", onboarding: { kycTier: 1, riskScore: "elevated" },
      paymentMethods: { ideal: "pending", creditcard: "active", paypal: "blocked" },
    },
  },
  invoices: { org_ACME0001: [], org_GLOBEX02: [] },
  webhooks: { org_ACME0001: [], org_GLOBEX02: [] },
  sessions: {}, // sessionId -> { userId, csrf }
};

// role -> what the UI advertises (used only to render the permission matrix).
const PERMISSION_MATRIX = {
  owner: { invoices: "manage", customers: "manage", profile: "manage", team: "manage" },
  viewer: { invoices: "view", customers: "view", profile: "no-access", team: "no-access" },
  support: { invoices: "view", customers: "view", profile: "no-access", team: "no-access" },
};

// ---------------------------------------------------------------------------
// Auth helpers
// ---------------------------------------------------------------------------
function currentSession(req) {
  const sid = req.cookies.SESSIONID;
  return sid ? db.sessions[sid] : undefined;
}
function currentUser(req) {
  const s = currentSession(req);
  return s ? Object.values(db.users).find((u) => u.id === s.userId) : undefined;
}
function requireAuth(req, res, next) {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: "not authenticated" });
  req.user = user;
  next();
}

// ---------------------------------------------------------------------------
// POST /api-internal/auth/login
// ---------------------------------------------------------------------------
app.post("/api-internal/auth/login", (req, res) => {
  const { email, password } = req.body || {};
  const user = db.users[String(email || "").toLowerCase()];
  if (!user || password !== "password123") {
    return res.status(401).json({ error: "invalid credentials" });
  }
  const sid = "sess_" + crypto.randomBytes(12).toString("hex");
  const csrf = crypto.randomBytes(16).toString("hex");
  db.sessions[sid] = { userId: user.id, csrf };
  res.cookie("SESSIONID", sid, { httpOnly: true, sameSite: "lax" });
  res.json({
    ok: true,
    user: { id: user.id, name: user.name, role: user.role, orgId: user.orgId, mfaEnabled: user.mfaEnabled },
    csrfToken: csrf,
    permissions: PERMISSION_MATRIX[user.role],
  });
});

app.get("/api-internal/auth/me", requireAuth, (req, res) => {
  const s = currentSession(req);
  res.json({
    user: { id: req.user.id, name: req.user.name, role: req.user.role, orgId: req.user.orgId, mfaEnabled: req.user.mfaEnabled },
    csrfToken: s.csrf,
    permissions: PERMISSION_MATRIX[req.user.role],
  });
});

// ===========================================================================
// LAB 01 — IDOR / Cross-Account Info Disclosure (mirrors Report 3)
// GET /api-internal/v2/invoice-ar/proxy?organizationId=<ORG>&path=customers
// BUG: the handler trusts organizationId from the query string and never
// checks that the caller is a member of that org.
// ===========================================================================
app.get("/api-internal/v2/invoice-ar/proxy", requireAuth, (req, res) => {
  const orgId = String(req.query.organizationId || "");
  const resource = String(req.query.path || "customers");
  // 🐞 MISSING AUTHORIZATION CHECK — should be:
  // if (req.user.orgId !== orgId) return res.status(403)...
  if (!db.organizations[orgId]) return res.status(404).json({ error: "org not found" });
  if (resource === "customers") {
    return res.json({ organizationId: orgId, customers: db.customers[orgId] || [] });
  }
  return res.status(400).json({ error: "unsupported path" });
});

// ===========================================================================
// LAB 02 — Race Condition / TOCTOU on webhook creation (mirrors Report 2)
// POST /api-internal/webhooks?organizationId=<ORG>
// BUG: "check the event type isn't already subscribed" and "insert the
// webhook" are separated by an await, with no lock. Fire N concurrent
// identical requests -> all pass the check -> duplicates created.
// ===========================================================================
const MAX_WEBHOOKS_PER_ORG = 5;
app.post("/api-internal/webhooks", requireAuth, async (req, res) => {
  const orgId = String(req.query.organizationId || req.user.orgId);
  const { url, name, eventTypes } = req.body || {};
  const wanted = String(eventTypes || "").split(",").map((s) => s.trim()).filter(Boolean);
  const list = db.webhooks[orgId] || (db.webhooks[orgId] = []);

  // --- CHECK (time-of-check) ---
  const already = new Set(list.flatMap((w) => w.eventTypes));
  const clash = wanted.find((e) => already.has(e));
  if (clash) return res.status(409).json({ error: `The event type ${clash} has been subscribed maximum amount of times` });
  if (list.length >= MAX_WEBHOOKS_PER_ORG) return res.status(409).json({ error: "webhook limit reached" });

  // 🐞 the vulnerable window: async gap between check and use, no mutex.
  await new Promise((r) => setTimeout(r, 40));

  // --- USE (time-of-use) ---
  const webhook = { id: "hook_" + crypto.randomBytes(4).toString("hex"), url, name, eventTypes: wanted, orgId };
  list.push(webhook);
  res.status(201).json({ ok: true, webhook, totalWebhooks: list.length });
});

app.get("/api-internal/webhooks", requireAuth, (req, res) => {
  const orgId = String(req.query.organizationId || req.user.orgId);
  res.json({ organizationId: orgId, webhooks: db.webhooks[orgId] || [] });
});

// ===========================================================================
// LAB 03 — Broken Access Control: Support role reads merchant profile
// (mirrors Report 4)
// GET /api-internal/profiles?organizationId=<ORG>
// BUG: the permission matrix says Support = "no-access" to profile/onboarding,
// but the endpoint only checks authentication, not role.
// ===========================================================================
app.get("/api-internal/profiles", requireAuth, (req, res) => {
  const orgId = String(req.query.organizationId || req.user.orgId);
  // 🐞 no role check — Support/Viewer should be denied here.
  const profile = db.profiles[orgId];
  if (!profile) return res.status(404).json({ error: "profile not found" });
  res.json({ profile });
});

// ===========================================================================
// LAB 04 — MFA not enforced server-side on destructive action
// (mirrors Report 5)
// DELETE /api-internal/v2/memberships/:id?organizationId=<ORG>
// BUG: docs say destructive team actions require MFA, but the server never
// checks user.mfaEnabled — a single-factor session is enough.
// ===========================================================================
app.delete("/api-internal/v2/memberships/:id", requireAuth, (req, res) => {
  const memId = req.params.id;
  const csrf = req.get("X-Csrf-Token");
  const s = currentSession(req);
  if (!csrf || csrf !== s.csrf) return res.status(403).json({ error: "bad csrf token" });
  // 🐞 MISSING: if (!req.user.mfaEnabled) return res.status(403, "MFA required")
  const membership = db.memberships[memId];
  if (!membership) return res.status(404).json({ error: "membership not found" });
  delete db.memberships[memId];
  res.json({ ok: true, removed: memId, mfaWasEnforced: false });
});

app.get("/api-internal/v2/memberships", requireAuth, (req, res) => {
  const orgId = String(req.query.organizationId || req.user.orgId);
  res.json({ memberships: Object.values(db.memberships).filter((m) => m.orgId === orgId) });
});

// ===========================================================================
// LAB 05 — Viewer privilege escalation: create + issue sales invoice
// (mirrors Report 6)
// POST /api-internal/v2/sales-invoices?organizationId=<ORG>
// BUG: the UI hides "Create invoice" for viewers, but the API performs no
// server-side role check, so a viewer can create/issue invoices.
// ===========================================================================
app.post("/api-internal/v2/sales-invoices", requireAuth, (req, res) => {
  const orgId = String(req.query.organizationId || req.user.orgId);
  const csrf = req.get("X-Csrf-Token");
  const s = currentSession(req);
  if (!csrf || csrf !== s.csrf) return res.status(403).json({ error: "bad csrf token" });
  // 🐞 MISSING: only owner/finance may create; viewer must be blocked.
  const { customerName, amount } = req.body || {};
  const invoice = {
    id: "inv_" + crypto.randomBytes(4).toString("hex"),
    orgId, customerName, amount: Number(amount) || 0,
    status: "issued", createdBy: req.user.role,
  };
  (db.invoices[orgId] || (db.invoices[orgId] = [])).push(invoice);
  res.status(201).json({ ok: true, invoice });
});

app.get("/api-internal/v2/sales-invoices", requireAuth, (req, res) => {
  const orgId = String(req.query.organizationId || req.user.orgId);
  res.json({ invoices: db.invoices[orgId] || [] });
});

// ===========================================================================
// LAB 06 — Client-side DoS via oversized logo dimensions (mirrors Report 1)
// POST /api-internal/branding/logo
// The server happily stores an image with attacker-declared dimensions; the
// DASHBOARD (public/app.js) then tries to decode/render it client-side and
// the tab freezes. The bug lives in the client — the API just accepts it.
// ===========================================================================
app.post("/api-internal/branding/logo", requireAuth, (req, res) => {
  const { width, height, dataUrl } = req.body || {};
  // 🐞 no sanity limit on dimensions before broadcasting to every org user.
  db.organizations[req.user.orgId].logo = { width, height, dataUrl };
  res.json({ ok: true, stored: { width, height }, note: "rendered client-side for every org member" });
});

app.get("/api-internal/branding/logo", requireAuth, (req, res) => {
  res.json({ logo: db.organizations[req.user.orgId].logo || null });
});

// ---------------------------------------------------------------------------
app.get("/healthz", (_req, res) => res.json({ ok: true }));

app.listen(PORT, () => {
  console.log(`\n InvoiceHub vulnerable lab running: http://localhost:${PORT}`);
  console.log(" Demo logins (password123):");
  console.log("   owner@acme.test    (owner, MFA on)");
  console.log("   viewer@acme.test   (viewer, MFA off)");
  console.log("   support@acme.test  (support, MFA off)");
  console.log("   owner@globex.test  (other tenant — the IDOR victim)\n");
});
