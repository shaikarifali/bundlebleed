from __future__ import annotations

import json
from pathlib import Path

from bundlebleed.models import ScanResult

_STYLE = """
:root {
  color-scheme: light;
  --page: #f9f9f7;
  --surface: #fcfcfb;
  --ink: #0b0b0b;
  --ink-secondary: #52514e;
  --ink-muted: #898781;
  --border: rgba(11, 11, 11, 0.10);
  --hairline: #e1e0d9;
  --accent: #2a78d6;
  --status-good: #0ca30c;
  --status-warning: #fab219;
  --status-serious: #ec835a;
  --status-critical: #d03b3b;
  --status-good-fg: #ffffff;
  --status-warning-fg: #1a1400;
  --status-serious-fg: #ffffff;
  --status-critical-fg: #ffffff;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    color-scheme: dark;
    --page: #0d0d0d;
    --surface: #1a1a19;
    --ink: #ffffff;
    --ink-secondary: #c3c2b7;
    --ink-muted: #898781;
    --border: rgba(255, 255, 255, 0.10);
    --hairline: #2c2c2a;
    --accent: #3987e5;
    --status-good: #0ca30c;
    --status-warning: #fab219;
    --status-serious: #ec835a;
    --status-critical: #e66767;
  }
}
:root[data-theme="dark"] {
  color-scheme: dark;
  --page: #0d0d0d;
  --surface: #1a1a19;
  --ink: #ffffff;
  --ink-secondary: #c3c2b7;
  --ink-muted: #898781;
  --border: rgba(255, 255, 255, 0.10);
  --hairline: #2c2c2a;
  --accent: #3987e5;
  --status-good: #0ca30c;
  --status-warning: #fab219;
  --status-serious: #ec835a;
  --status-critical: #e66767;
}

* { box-sizing: border-box; }
body {
  background: var(--page);
  color: var(--ink);
  font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
  padding: 24px 16px 64px;
  max-width: 1200px;
  margin: 0 auto;
}
h1 { font-size: 1.4rem; margin: 0 0 4px; }
h2 { font-size: 1.05rem; margin: 32px 0 12px; }
.meta { color: var(--ink-secondary); font-size: 0.85rem; margin-bottom: 20px; }
.meta code {
  background: var(--surface); border: 1px solid var(--border);
  padding: 1px 5px; border-radius: 4px;
}

.tiles {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 10px;
  margin-bottom: 8px;
}
.tile {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 12px 14px;
}
.tile .label { color: var(--ink-secondary); font-size: 0.78rem; }
.tile .value { font-size: 1.6rem; font-weight: 600; margin-top: 2px; }

.search {
  position: sticky;
  top: 0;
  background: var(--page);
  padding: 10px 0;
  z-index: 5;
}
.search input {
  width: 100%;
  padding: 9px 12px;
  border-radius: 8px;
  border: 1px solid var(--border);
  background: var(--surface);
  color: var(--ink);
  font-size: 0.9rem;
}

.table-wrap { overflow-x: auto; border: 1px solid var(--border); border-radius: 10px; }
table { border-collapse: collapse; width: 100%; font-size: 0.85rem; }
th, td {
  padding: 8px 10px; text-align: left;
  border-bottom: 1px solid var(--hairline); vertical-align: top;
}
th {
  color: var(--ink-secondary); font-weight: 600; cursor: pointer;
  white-space: nowrap; user-select: none;
}
th:hover { color: var(--ink); }
th .arrow { color: var(--ink-muted); font-size: 0.75em; margin-left: 3px; }
td code { background: var(--surface); border-radius: 4px; padding: 1px 4px; }
tr:last-child td { border-bottom: none; }
.empty { color: var(--ink-muted); font-style: italic; padding: 14px; }

.badge {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 999px;
  font-size: 0.75rem;
  font-weight: 600;
  white-space: nowrap;
}
.badge-critical { background: var(--status-critical); color: var(--status-critical-fg); }
.badge-high, .badge-serious {
  background: var(--status-serious); color: var(--status-serious-fg);
}
.badge-medium, .badge-warning {
  background: var(--status-warning); color: var(--status-warning-fg);
}
.badge-low, .badge-good { background: var(--status-good); color: var(--status-good-fg); }
.badge-neutral { background: var(--hairline); color: var(--ink-secondary); }
"""

_SCRIPT = """
const DATA = window.__BUNDLEBLEED_SCAN__;

function badge(text) {
  const key = String(text || "").toLowerCase();
  const known = ["critical", "high", "medium", "low", "serious", "warning", "good"];
  const cls = known.includes(key) ? "badge-" + key : "badge-neutral";
  const span = document.createElement("span");
  span.className = "badge " + cls;
  span.textContent = text;
  return span;
}

function cellValue(row, col) {
  const v = col.get ? col.get(row) : row[col.key];
  return v === null || v === undefined ? "" : v;
}

function renderTable(containerId, rows, columns, emptyText) {
  const container = document.getElementById(containerId);
  if (!rows || rows.length === 0) {
    const p = document.createElement("p");
    p.className = "empty";
    p.textContent = emptyText || "None found.";
    container.appendChild(p);
    return;
  }

  const wrap = document.createElement("div");
  wrap.className = "table-wrap";
  const table = document.createElement("table");
  const thead = document.createElement("thead");
  const headRow = document.createElement("tr");
  let sortState = { index: -1, dir: 1 };

  columns.forEach((col, i) => {
    const th = document.createElement("th");
    th.textContent = col.label;
    th.addEventListener("click", () => {
      sortState = { index: i, dir: sortState.index === i ? -sortState.dir : 1 };
      sortRows();
      renderBody();
    });
    headRow.appendChild(th);
  });
  thead.appendChild(headRow);
  table.appendChild(thead);

  const tbody = document.createElement("tbody");
  table.appendChild(tbody);
  wrap.appendChild(table);
  container.appendChild(wrap);

  let currentRows = rows.slice();

  function sortRows() {
    if (sortState.index < 0) return;
    const col = columns[sortState.index];
    currentRows.sort((a, b) => {
      const av = cellValue(a, col);
      const bv = cellValue(b, col);
      if (av < bv) return -1 * sortState.dir;
      if (av > bv) return 1 * sortState.dir;
      return 0;
    });
  }

  function renderBody() {
    tbody.innerHTML = "";
    const query = (window.__BUNDLEBLEED_QUERY__ || "").toLowerCase();
    currentRows.forEach((row) => {
      const rowText = columns.map((c) => String(cellValue(row, c))).join(" ").toLowerCase();
      if (query && !rowText.includes(query)) return;
      const tr = document.createElement("tr");
      columns.forEach((col) => {
        const td = document.createElement("td");
        const value = cellValue(row, col);
        if (col.badge) {
          td.appendChild(badge(value));
        } else if (col.code) {
          const code = document.createElement("code");
          code.textContent = value;
          td.appendChild(code);
        } else {
          td.textContent = value;
        }
        tr.appendChild(td);
      });
      tbody.appendChild(tr);
    });
    if (!tbody.children.length) {
      const tr = document.createElement("tr");
      const td = document.createElement("td");
      td.colSpan = columns.length;
      td.className = "empty";
      td.textContent = "No rows match your search.";
      tr.appendChild(td);
      tbody.appendChild(tr);
    }
  }

  container.__rerender = renderBody;
  renderBody();
}

const allRerenders = [];
function mount(containerId, rows, columns, emptyText) {
  renderTable(containerId, rows, columns, emptyText);
  const el = document.getElementById(containerId);
  if (el.__rerender) allRerenders.push(el.__rerender);
}

document.getElementById("search-box").addEventListener("input", (e) => {
  window.__BUNDLEBLEED_QUERY__ = e.target.value;
  allRerenders.forEach((fn) => fn());
});

mount("hypotheses-table", DATA.hypotheses, [
  { key: "risk", label: "Risk", badge: true },
  { key: "confidence", label: "Confidence", get: (r) => r.confidence.toFixed(2) },
  { key: "status", label: "Status" },
  { key: "bug_classes", label: "Bug classes", get: (r) => r.bug_classes.join(", ") },
  { key: "target_value", label: "Target", code: true },
  { key: "proposed_test", label: "Proposed test" },
], "No hypotheses generated.");

mount("secrets-table", DATA.secrets, [
  { key: "secret_type", label: "Type" },
  { key: "severity", label: "Severity", badge: true },
  { key: "redacted_value", label: "Redacted value", code: true },
  { key: "source_url", label: "Source" },
], "No secrets found.");

mount("endpoints-table", DATA.endpoints, [
  { key: "value", label: "Value", code: true },
  { key: "pattern_name", label: "Pattern" },
  { key: "source_url", label: "Source" },
], "No endpoints found.");

mount("subdomains-table", DATA.subdomains, [
  { key: "domain", label: "Domain" },
  { key: "in_scope", label: "In scope", get: (r) => (r.in_scope ? "yes" : "no") },
  { key: "note", label: "Note" },
  { key: "source_url", label: "Source" },
], "No subdomains found.");

mount("parameters-table", DATA.parameters, [
  { key: "name", label: "Name", code: true },
  { key: "source_url", label: "Source" },
], "No parameters found.");

mount("dom-table", DATA.dom_findings, [
  { key: "sink_pattern", label: "Sink" },
  { key: "sink_value", label: "Matched", code: true },
  {
    key: "co_occurring_sources", label: "Co-occurring sources",
    get: (r) => r.co_occurring_sources.join(", "),
  },
  { key: "source_url", label: "Source" },
], "No DOM findings.");

mount("cors-table", DATA.cors_findings, [
  { key: "source_url", label: "Source" },
  { key: "allow_origin", label: "Allow-Origin" },
  {
    key: "allow_credentials", label: "Allow-Credentials",
    get: (r) => (r.allow_credentials ? "true" : "false"),
  },
], "No CORS misconfigurations found.");

mount("third-party-scripts-table", DATA.third_party_scripts, [
  { key: "hostname", label: "Hostname" },
  { key: "script_url", label: "Script URL" },
  { key: "page_url", label: "Page" },
], "No third-party scripts found.");

mount("postmessage-table", DATA.postmessage_findings, [
  { key: "source_url", label: "Source" },
  { key: "snippet_preview", label: "Snippet", code: true },
], "No postMessage findings.");

mount("websocket-table", DATA.websocket_findings, [
  { key: "source_url", label: "Source" },
  { key: "snippet_preview", label: "Snippet", code: true },
], "No WebSocket findings.");

mount("files-table", DATA.files, [
  { key: "url", label: "URL" },
  { key: "frameworks", label: "Frameworks", get: (r) => r.frameworks.join(", ") },
  {
    key: "source_map_found", label: "Source map",
    get: (r) => (r.source_map_found ? "yes" : "no"),
  },
  {
    key: "discovered_via_session", label: "Session",
    get: (r) => r.discovered_via_session || "-",
  },
  {
    key: "discovered_via_runtime", label: "Runtime",
    get: (r) => (r.discovered_via_runtime ? "yes" : "no"),
  },
  {
    key: "recovered_from_source_map", label: "Recovered source",
    get: (r) => (r.recovered_from_source_map ? "yes" : "no"),
  },
], "No files downloaded.");

mount("ai-verdicts-table", DATA.ai_verdicts, [
  { key: "priority", label: "Priority", badge: true },
  { key: "confidence", label: "Confidence", get: (r) => r.confidence.toFixed(2) },
  { key: "bug_classes", label: "Bug classes", get: (r) => r.bug_classes.join(", ") },
  { key: "endpoint_value", label: "Endpoint", code: true },
  { key: "test_plan", label: "Test plan" },
  { key: "model", label: "Model" },
], "No AI analysis run.");
"""


def render_html(result: ScanResult) -> str:
    r = result.normalized()
    data = json.loads(r.model_dump_json())

    tiles = [
        ("Targets", len(r.targets)),
        ("URLs collected", len(r.collected_urls)),
        ("JS files", len(r.files)),
        ("Endpoints", len(r.endpoints)),
        ("Secrets", len(r.secrets)),
        ("Subdomains", len(r.subdomains)),
        ("CORS misconfigurations", len(r.cors_findings)),
        ("Third-party scripts", len(r.third_party_scripts)),
        ("PostMessage findings", len(r.postmessage_findings)),
        ("WebSocket findings", len(r.websocket_findings)),
        ("Hypotheses", len(r.hypotheses)),
    ]
    tiles_html = "".join(
        f'<div class="tile"><div class="label">{label}</div><div class="value">{value}</div></div>'
        for label, value in tiles
    )

    targets_str = ", ".join(r.targets) or "(none)"

    return f"""<title>BundleBleed Scan Report</title>
<style>{_STYLE}</style>
<h1>BundleBleed Scan Report</h1>
<div class="meta">
  Scan <code>{r.scan_run_id}</code> &middot; started {r.started_at.isoformat()}
  &middot; targets: {targets_str}
</div>
<div class="tiles">{tiles_html}</div>
<div class="search"><input id="search-box" type="text" placeholder="Filter every table..." /></div>

<h2>Hypotheses</h2>
<div id="hypotheses-table"></div>

<h2>Secrets</h2>
<div id="secrets-table"></div>

<h2>Endpoints</h2>
<div id="endpoints-table"></div>

<h2>Subdomains</h2>
<div id="subdomains-table"></div>

<h2>Parameters</h2>
<div id="parameters-table"></div>

<h2>DOM findings</h2>
<div id="dom-table"></div>

<h2>CORS misconfigurations</h2>
<div id="cors-table"></div>

<h2>Third-party scripts</h2>
<div id="third-party-scripts-table"></div>

<h2>PostMessage findings</h2>
<div id="postmessage-table"></div>

<h2>WebSocket findings</h2>
<div id="websocket-table"></div>

<h2>Files analyzed</h2>
<div id="files-table"></div>

<h2>AI endpoint analysis</h2>
<div id="ai-verdicts-table"></div>

<script>
window.__BUNDLEBLEED_SCAN__ = {json.dumps(data)};
</script>
<script>{_SCRIPT}</script>
"""


def write_html_report(result: ScanResult, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "scan-result.html"
    path.write_text(render_html(result))
    return path
