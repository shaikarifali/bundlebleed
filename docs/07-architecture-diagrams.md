# Architecture Diagrams

Visual companions to [How It Works](02-how-it-works.md) and
[Architecture & Extending](04-architecture.md) — read those for the prose
explanation of anything below. These render as actual diagrams on GitHub
(Mermaid is supported natively in Markdown); if you're reading this in a
plain text editor instead, the prose docs linked above cover the same
ground without needing a renderer.

## 1. The full scan pipeline

Every stage after COLLECT runs on data already downloaded and
scope-checked — nothing downstream makes its own network request.

```mermaid
flowchart TD
    T["Target domain"] --> C{"Collect"}
    C -->|"passive, always"| P["gau + waybackurls +<br/>waymore + paramspider"]
    C -->|"active, 3-gate authorized"| K["katana"]
    SEED["--seed-url /<br/>--seed-url-file"] --> SG
    P --> SG{"ScopeGuard.check()"}
    K --> SG
    SEED --> SG
    SG -->|"DENY"| LOG[("audit_log.jsonl")]
    SG -->|"ALLOW"| DL["Download JS + pages"]
    DL --> EX["Extract"]
    EX --> EP["13 endpoint patterns"]
    EX --> SP["57 secret patterns"]
    EX --> DOM["DOM sink/source pairs"]
    EX --> GQL["GraphQL operations"]
    EX --> OTHER["CORS, mass-assignment,<br/>vuln libs, subdomains"]
    EP --> DEDUP["deduplicate_endpoints()"]
    DEDUP --> CTX["Context"]
    SP --> CTX
    DOM --> CTX
    GQL --> CTX
    OTHER --> CTX
    CTX --> RT["Runtime capture<br/>(optional, headless Chromium)"]
    CTX --> HIST["Historical<br/>cross-scan match"]
    RT --> HYP["Hypothesis engine<br/>7-factor scoring"]
    HIST --> HYP
    HYP --> AI[["Optional AI layer<br/>classify / report / chains"]]
    AI --> HYP
    HYP --> VER["Verification drafter<br/>(drafts, never sends)"]
    HYP --> OUT["Reports: JSON / MD / HTML<br/>wordlists, evidence bundles"]
    VER --> HUMAN["A human runs the test"]
    HUMAN --> RECORD["verify record<br/>confirmed / rejected / inconclusive"]
```

**Read it as:** four passive archive sources feed in freely; the one active
crawler (`katana`) only joins if all three authorization gates hold. Every
single URL from any source — passive, active, or a `--seed-url` — passes
through the same `ScopeGuard.check()` before anything downloads it. From
there, extraction fans out into several independent detectors, endpoints
get deduplicated across files, and everything converges on one scoring
engine before an optional AI layer and a strictly human-gated verification
step.

## 2. Module architecture

Which package depends on which. `cli.py` is the only thing that talks to
all of them; packages don't reach into each other except where shown.

```mermaid
flowchart LR
    CLI["cli.py"] --> COL["collectors/"]
    CLI --> SCOPE["scope/"]
    CLI --> DL["downloader/"]
    CLI --> AUTH["auth/"]
    CLI --> PROC["processors/"]
    CLI --> EXT["extractors/"]
    CLI --> RT["runtime/"]
    CLI --> KNOW["knowledge/"]
    CLI --> HYP["hypotheses/"]
    CLI --> AI["ai/"]
    CLI --> VER["verification/"]
    CLI --> HIST["history/"]
    CLI --> MON["monitoring/"]
    CLI --> REP["reporters/"]

    COL --> SCOPE
    DL --> SCOPE
    RT --> SCOPE
    AUTH --> DL
    EXT --> DATA["data/<br/>(YAML patterns)"]
    HYP --> EXT
    HYP --> KNOW
    AI --> HYP
    VER --> HYP
    REP --> HYP
    MON --> HIST
```

**Read it as:** `scope/` is the one package almost everything that touches
the network depends on — `collectors/`, `downloader/`, and `runtime/` all
route through `ScopeGuard` rather than calling out directly.
`hypotheses/` is the hub on the other side: it consumes `extractors/`
output and `knowledge/`'s cross-referencing, and everything downstream
(`ai/`, `verification/`, `reporters/`) depends on *it*, not on the raw
extractors. Adding a new pattern only touches `extractors/` + `data/`;
adding a new bug class touches `hypotheses/engine.py` too — see
[Architecture § Adding a detection pattern](04-architecture.md#adding-a-detection-pattern--no-python-required).

## 3. The scoring engine

How seven independent signals become one confidence score and a risk tier.

```mermaid
flowchart LR
    subgraph SIGNALS["Seven independent signals"]
        S1["Discovery pattern match<br/>+0.20"]
        S2["Bug-class rule match<br/>+0.20 (gating)"]
        S3["JS-body-only visibility<br/>+0.15"]
        S4["Authenticated context<br/>+0.20"]
        S5["Historical cross-scan match<br/>+0.10"]
        S6["Runtime-confirmed<br/>+0.30"]
        S7["AI confidence, capped<br/>+0.10 max"]
    end
    S1 --> SUM(("score_confidence()<br/>capped at 1.0"))
    S2 --> SUM
    S3 --> SUM
    S4 --> SUM
    S5 --> SUM
    S6 --> SUM
    S7 --> SUM
    SUM --> TIER{"risk_for_confidence()"}
    TIER -->|">= 0.6"| HIGH["High"]
    TIER -->|">= 0.35"| MED["Medium"]
    TIER -->|"else"| LOW["Low"]
```

**Read it as:** "Bug-class rule match" is doubly important — it's both a
scoring signal *and* the literal gate (`if not rule_match: continue` in
`hypotheses/engine.py`) that decides whether an endpoint becomes a
hypothesis at all. The other six only ever adjust the score of something
that already cleared that gate. Full weight table and exact thresholds:
[How It Works § The hypothesis / scoring engine](02-how-it-works.md#the-hypothesis--scoring-engine).
