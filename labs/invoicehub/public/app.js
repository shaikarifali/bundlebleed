/* ==========================================================================
 * InvoiceHub SPA bundle (public/app.js)
 * --------------------------------------------------------------------------
 * This is the file a JS-recon tool like BundleBleed downloads and mines.
 * Notice how many /api-internal/* routes are referenced here that a user
 * clicking around the UI would NEVER discover — those hidden endpoints are
 * exactly where the bugs live. That is the whole point of the demo.
 * ======================================================================== */

// --- API surface map -------------------------------------------------------
// Some of these are wired to visible buttons. Others are "internal", behind
// feature flags, or only used by admin tooling — hidden from the UI but very
// much reachable. BundleBleed will surface ALL of them from this bundle.
const API = {
  login: "/api-internal/auth/login",
  me: "/api-internal/auth/me",

  // visible-ish
  listInvoices: "/api-internal/v2/sales-invoices",
  createInvoice: "/api-internal/v2/sales-invoices", // LAB 05 (viewer priv-esc)
  listWebhooks: "/api-internal/webhooks",
  createWebhook: "/api-internal/webhooks", // LAB 02 (race condition)
  listTeam: "/api-internal/v2/memberships",
  deleteMember: "/api-internal/v2/memberships/{id}", // LAB 04 (MFA not enforced)
  uploadLogo: "/api-internal/branding/logo", // LAB 06 (client-side DoS)

  // 🔒 HIDDEN / INTERNAL — no button in the UI points here. Jackpot territory.
  customerProxy: "/api-internal/v2/invoice-ar/proxy", // LAB 01 (IDOR cross-account)
  merchantProfile: "/api-internal/profiles", // LAB 03 (broken access control)

  // extra decoys / recon bait — dead references left in the bundle
  adminExport: "/api-internal/admin/v3/export-all-tenants",
  featureFlags: "/api-internal/config/feature-flags",
  legacyBilling: "/api/v1/legacy/billing/run-settlement",
};

// --- Recon bait: a leftover "test" key in the bundle -----------------------
// (Fake, non-functional. Demonstrates BundleBleed's secret scanner.)
// NOTE for demo presenters, on the three values below -- each one is
// deliberately shaped to avoid a different way BundleBleed's own noise
// filters would otherwise swallow it:
//   - posthogKey uses the 'phx_' *personal* key prefix, not the
//     intentionally-public 'phc_' project key every PostHog site ships.
//   - stagingToken is exactly 24 chars after 'sk_test_' -- real Stripe
//     keys always are, and a longer fake value would also satisfy
//     clerk_secret_key's 40+-char pattern and get double-matched.
//   - internalGateway's domain avoids the word that a scrubbed real
//     secret often literally contains (see extractors/secrets.py's
//     _FALSE_POSITIVE_CONTEXT_RE) -- using it here would silently
//     suppress this exact finding.
const ANALYTICS_CONFIG = {
  posthogKey: "phx_0FAKE0fake0FAKE0fake0FAKE0fake0FAKE0fake000",
  // TODO(remove before prod): staging service token
  stagingToken: "sk_test_00FAKE0fake0FAKE0fake000",
  internalGateway: "https://api-internal.staging.acmecorp.com",
};

let state = { user: null, csrf: null, permissions: null };

// --- helpers -----------------------------------------------------------
async function api(url, opts = {}) {
  const res = await fetch(url, {
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      ...(state.csrf ? { "X-Csrf-Token": state.csrf } : {}),
      ...(opts.headers || {}),
    },
    ...opts,
  });
  return res.json();
}
const $ = (id) => document.getElementById(id);
const el = (html) => { const d = document.createElement("div"); d.innerHTML = html.trim(); return d.firstElementChild; };

// --- auth --------------------------------------------------------------
async function login() {
  $("login-error").textContent = "";
  const r = await api(API.login, {
    method: "POST",
    body: JSON.stringify({ email: $("email").value, password: $("password").value }),
  });
  if (!r.ok) { $("login-error").textContent = r.error || "login failed"; return; }
  state.user = r.user; state.csrf = r.csrfToken; state.permissions = r.permissions;
  renderDashboard();
}

function renderDashboard() {
  $("login-view").hidden = true;
  $("dash-view").hidden = false;
  $("who-name").textContent = state.user.name;
  const roleEl = $("who-role"); roleEl.textContent = state.user.role;
  roleEl.className = "pill role";
  const mfaEl = $("who-mfa");
  mfaEl.textContent = state.user.mfaEnabled ? "MFA on" : "MFA off";
  mfaEl.className = "pill " + (state.user.mfaEnabled ? "mfa-on" : "mfa-off");
  selectTab("invoices");
}

// --- tabs ----------------------------------------------------------------
function selectTab(tab) {
  document.querySelectorAll(".tab").forEach((b) => b.classList.toggle("active", b.dataset.tab === tab));
  const panel = $("panel");
  panel.innerHTML = "";
  ({ invoices: renderInvoices, customers: renderCustomers, webhooks: renderWebhooks,
     team: renderTeam, branding: renderBranding }[tab] || renderInvoices)(panel);
}

// --- Invoices (LAB 05) -----------------------------------------------------
async function renderInvoices(panel) {
  const canCreate = state.permissions.invoices === "manage";
  panel.append(el(`<div>
    <h3 class="section-title">Sales invoices</h3>
    <p class="section-sub">Permission model says your role is: <b>${state.permissions.invoices}</b></p>
  </div>`));

  // The UI hides "Create invoice" for viewers — but the API doesn't check.
  if (canCreate) {
    panel.append(makeInvoiceForm());
  } else {
    panel.append(el(`<div class="notice">Your role is view-only for invoices, so no "Create" button is shown.
      (LAB 05: the <code>${API.createInvoice}</code> endpoint still accepts your request — try it from the console.)</div>`));
  }

  const data = await api(`${API.listInvoices}?organizationId=${state.user.orgId}`);
  const rows = (data.invoices || []).map((i) =>
    `<tr><td>${i.id}</td><td>${i.customerName}</td><td>€${i.amount}</td><td class="tag-ok">${i.status}</td><td>${i.createdBy}</td></tr>`).join("");
  panel.append(el(`<table><thead><tr><th>ID</th><th>Customer</th><th>Amount</th><th>Status</th><th>Created by</th></tr></thead><tbody>${rows || ""}</tbody></table>`));
}

function makeInvoiceForm() {
  const wrap = el(`<div class="tile"><h4>Create invoice</h4>
    <label>Customer <input id="inv-cust" value="Walk-in Customer"></label>
    <label>Amount (€) <input id="inv-amt" value="500"></label>
    <button id="inv-create">Create & issue</button></div>`);
  wrap.querySelector("#inv-create").onclick = async () => {
    await api(`${API.createInvoice}?organizationId=${state.user.orgId}`, {
      method: "POST",
      body: JSON.stringify({ customerName: wrap.querySelector("#inv-cust").value, amount: wrap.querySelector("#inv-amt").value }),
    });
    selectTab("invoices");
  };
  return wrap;
}

// --- Customers (LAB 01: hidden proxy endpoint) -----------------------------
async function renderCustomers(panel) {
  panel.append(el(`<div>
    <h3 class="section-title">Customers</h3>
    <p class="section-sub">Loaded via the internal proxy: <code>${API.customerProxy}</code></p>
  </div>`));

  // The UI only ever passes YOUR org — but the endpoint trusts whatever you send.
  const data = await api(`${API.customerProxy}?organizationId=${state.user.orgId}&path=customers`);
  const rows = (data.customers || []).map((c) =>
    `<tr><td>${c.name}</td><td>${c.email}</td><td>${c.iban}</td><td>€${c.spend}</td></tr>`).join("");
  panel.append(el(`<table><thead><tr><th>Name</th><th>Email</th><th>IBAN</th><th>Spend</th></tr></thead><tbody>${rows}</tbody></table>`));
  panel.append(el(`<div class="notice">LAB 01: swap <code>organizationId</code> to another tenant
    (e.g. <span class="kbd">org_GLOBEX02</span>) and the server returns THEIR customers. No membership check.</div>`));
}

// --- Webhooks (LAB 02) -----------------------------------------------------
async function renderWebhooks(panel) {
  panel.append(el(`<div><h3 class="section-title">Webhooks</h3>
    <p class="section-sub">Max ${5} per org · duplicate event types rejected — unless you race them.</p></div>`));
  const form = el(`<div class="tile"><h4>Create webhook</h4>
    <label>Name <input id="wh-name" value="Web 3"></label>
    <label>URL <input id="wh-url" value="https://abc.example.com/hook"></label>
    <label>Event types <input id="wh-ev" value="payment-link.paid"></label>
    <button id="wh-create">Create</button></div>`);
  form.querySelector("#wh-create").onclick = async () => {
    await api(`${API.createWebhook}?organizationId=${state.user.orgId}`, {
      method: "POST",
      body: JSON.stringify({ name: form.querySelector("#wh-name").value, url: form.querySelector("#wh-url").value, eventTypes: form.querySelector("#wh-ev").value }),
    });
    selectTab("webhooks");
  };
  panel.append(form);
  const data = await api(`${API.listWebhooks}?organizationId=${state.user.orgId}`);
  const rows = (data.webhooks || []).map((w) =>
    `<tr><td>${w.id}</td><td>${w.name}</td><td>${w.eventTypes.join(", ")}</td></tr>`).join("");
  panel.append(el(`<table><thead><tr><th>ID</th><th>Name</th><th>Event types</th></tr></thead><tbody>${rows}</tbody></table>`));
  panel.append(el(`<div class="notice">LAB 02: fire ~20 identical create requests concurrently to beat the check-then-insert window. See <code>challenges/02-race-condition-webhooks.md</code>.</div>`));
}

// --- Team (LAB 04) ---------------------------------------------------------
async function renderTeam(panel) {
  panel.append(el(`<div><h3 class="section-title">Team</h3>
    <p class="section-sub">Docs say destructive actions require MFA. The server disagrees.</p></div>`));
  const data = await api(`${API.listTeam}?organizationId=${state.user.orgId}`);
  const table = el(`<table><thead><tr><th>Membership</th><th>Role</th><th></th></tr></thead><tbody></tbody></table>`);
  (data.memberships || []).forEach((m) => {
    const tr = el(`<tr><td>${m.id}</td><td>${m.role}</td><td><button class="ghost">Remove</button></td></tr>`);
    tr.querySelector("button").onclick = async () => {
      const r = await api(API.deleteMember.replace("{id}", m.id) + `?organizationId=${state.user.orgId}`, { method: "DELETE" });
      alert(JSON.stringify(r));
      selectTab("team");
    };
    table.querySelector("tbody").append(tr);
  });
  panel.append(table);
  panel.append(el(`<div class="notice">LAB 04: this succeeds even when your MFA is OFF (<code>${API.deleteMember}</code>).</div>`));
}

// --- Branding (LAB 06) -----------------------------------------------------
function renderBranding(panel) {
  panel.append(el(`<div><h3 class="section-title">Branding</h3>
    <p class="section-sub">Upload an org logo. It renders for every member. What if it's 63,240 × 63,240?</p></div>`));
  const form = el(`<div class="tile"><h4>Upload logo (declared dimensions)</h4>
    <label>Width <input id="lg-w" value="256"></label>
    <label>Height <input id="lg-h" value="256"></label>
    <button id="lg-up">Upload</button>
    <button id="lg-render" class="ghost">Render preview</button></div>`);
  const preview = el(`<div class="tile"><h4>Preview</h4><canvas id="lg-canvas" width="256" height="256" style="max-width:100%;border:1px solid var(--line)"></canvas></div>`);
  form.querySelector("#lg-up").onclick = async () => {
    const w = Number(form.querySelector("#lg-w").value), h = Number(form.querySelector("#lg-h").value);
    const r = await api(API.uploadLogo, { method: "POST", body: JSON.stringify({ width: w, height: h, dataUrl: "demo" }) });
    alert(JSON.stringify(r));
  };
  form.querySelector("#lg-render").onclick = () => {
    const w = Number(form.querySelector("#lg-w").value), h = Number(form.querySelector("#lg-h").value);
    const c = preview.querySelector("#lg-canvas");
    // 🐞 client-side DoS: allocating an attacker-sized canvas freezes the tab.
    c.width = w; c.height = h;
    const ctx = c.getContext("2d");
    ctx.fillStyle = "#c1121f"; ctx.fillRect(0, 0, w, h); // huge fill = jank/hang
  };
  panel.append(form, preview);
  panel.append(el(`<div class="notice">LAB 06: set width/height to a huge value (e.g. 30000) and hit "Render preview" — watch the tab hang. Real bug: server never caps dimensions before broadcasting to every org user.</div>`));
}

// --- boot ------------------------------------------------------------------
document.addEventListener("click", (e) => {
  if (e.target.matches(".tab")) selectTab(e.target.dataset.tab);
});
window.addEventListener("DOMContentLoaded", () => {
  $("login-btn").onclick = login;
  $("logout-btn").onclick = () => location.reload();
});
