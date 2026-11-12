# Getting Started

This page assumes no prior familiarity with JS recon. If you already know
what "JS recon" means and just want the tool running, skip to
[Installation](#installation).

## What is JavaScript recon, and why does it matter?

Every modern web app ships a lot of its logic to your browser as JavaScript
— that's what lets a single-page app feel instant instead of reloading the
whole page for every click. To do that, the JS file has to contain, in
plain text (or lightly obfuscated "minified" text), **every API endpoint
the app is capable of calling** — including ones that no button in the UI
ever links to.

That last part is the whole reason this tool exists. A feature-flagged admin
panel, a legacy `/api/v1/` route nobody updated the frontend to stop using,
an internal gateway meant for other services — none of them show up if you
just click around the app. All of them are sitting in the JS bundle,
in plain text, because the browser has to be able to call them.

**The one-sentence pitch:** *the UI is the lie, the bundle is the truth.*

## What BundleBleed actually does with that

1. Downloads the target's JS (and, optionally, crawls more of it)
2. Extracts endpoints, secrets, and known-risky code patterns from it
3. Scores each finding so you see the handful worth testing, not all of them
4. Optionally drafts a report — but never tests, exploits, or sends anything
   itself

You still do the actual hacking. BundleBleed does the reading.

## Installation

Requires Python 3.12+ and [`uv`](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/shaikarifali/bundlebleed
cd bundlebleed
uv sync
```

That's the whole install. No API key, no account, no config file needed to
run your first scan.

**Optional — only if you want authenticated headless-browser capture later**
(see [How It Works](02-how-it-works.md#runtime-capture)):

```bash
uv sync --extra runtime
uv run playwright install chromium
```

## Your first scan

```bash
uv run bundlebleed scan -t example.com -o results/
```

Replace `example.com` with a target **you are authorized to test** — your
own site, a bug-bounty program's in-scope domain, or a lab environment. See
[Legal](../README.md#legal) in the main README; BundleBleed enforces the
scope you give it, but it cannot know whether that scope is actually
authorized. That's on you.

What happens:

1. It queries public archives (`gau`, `waybackurls`, `waymore`,
   `paramspider`) for every URL ever seen for that domain — no requests to
   the target itself yet.
2. Every one of those URLs is checked against your declared scope before
   anything downloads it.
3. It downloads the JS files that survived, and reads them.
4. It prints a summary and writes a few report files.

A real run looks like this:

```text
collected 41 in-scope URLs, dropped 3 out-of-scope
downloaded 6 JS files (2 original source file(s) recovered from source maps), 0 page bodies
found 34 candidate endpoints, 2 candidate secrets
found 3 subdomains, 8 parameters, 1 DOM findings
12 hypotheses generated, evidence bundles written under results/evidence (12 file(s))
reports written to results/scan-result.json, results/scan-result.md, and results/scan-result.html
wordlists written to results/wordlists/ (urls/endpoints/parameters/subdomains/third-party-hosts.txt)
```

## Reading the output

Open `results/scan-result.html` in a browser first — it's a self-contained
dashboard (works straight from `file://`, no server needed). Look at the
**hypotheses** section: each one has a **confidence score** (0 to 1) and a
**risk tier** (low / medium / high). Start at the top.

A few terms you'll see everywhere:

| Term | Meaning |
|---|---|
| **Endpoint** | A candidate API path/URL extracted from the JS |
| **Secret** | A credential-shaped string, redacted (never the raw value) |
| **Hypothesis** | An endpoint or secret that cleared a bug-class gate and got scored |
| **Confidence** | 0–1 score from combining independent signals — see [How It Works](02-how-it-works.md) |
| **Risk tier** | low / medium / high, derived from the confidence score |
| **Evidence chain** | The specific reasons a hypothesis got the score it did |
| **ScopeGuard** | The single choke point every outbound request passes through |

Each hypothesis's directory under `results/evidence/<id>/finding.json`
has the full detail — pattern matched, evidence chain, and (never a live
credential) a redacted preview if it's a secret.

## What to do next

Pick the highest-confidence hypothesis and go read `finding.json` for it.
BundleBleed never tests anything for you — from here it's you, Burp, and
your own judgment. If the finding needs a real test request,
`bundlebleed verify diff` and `bundlebleed verify record` (see the
[CLI reference](05-cli-reference.md)) give you a lightweight way to log a
confirmed/rejected outcome once you've manually checked it.

When you're ready for the mechanics of *why* something scored the way it
did, move on to [How It Works](02-how-it-works.md).
