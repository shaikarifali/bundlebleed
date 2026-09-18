# BundleBleed Documentation

The main [README](../README.md) is the pitch and quickstart. This folder is
the deep reference — split by how much you already know, so nobody has to
wade through architecture internals just to run their first scan, and nobody
who wants the internals has to dig through beginner explanations to find them.

## Start here

**New to JS recon, or new to BundleBleed?**
→ [01 — Getting Started](01-getting-started.md)
What JavaScript recon actually is, installing the tool, your first scan,
and how to read the output.

**Comfortable running scans, want to know what's actually happening?**
→ [02 — How It Works](02-how-it-works.md)
The real pipeline, the scoring engine's exact math, and the safety gates
that keep it from ever touching exploitation.

**Want the exhaustive list of everything it can find?**
→ [03 — Detection Reference](03-detection-reference.md)
All 13 endpoint patterns, all 57 secret patterns, all 14 named bug classes,
DOM sinks/sources, vulnerable-library CVEs — the full table.

**Building on top of it, or contributing?**
→ [04 — Architecture & Extending](04-architecture.md)
Module map, how to add a detection pattern without touching Python, how
the identity/dedup/scoring internals fit together, contribution guide.

**Just need the flags?**
→ [05 — CLI Reference](05-cli-reference.md)
Every command, every flag, grouped by what they do.

**Have a question someone already asked?**
→ [06 — FAQ](06-faq.md)

## One-paragraph orientation, regardless of tier

BundleBleed downloads the JavaScript a target application ships to the
browser and turns it into a small, ranked list of security hypotheses
instead of a pile of grep hits. The differentiator isn't discovery — wrapping
`gau`/`waybackurls`/`katana`/`waymore`/`paramspider` for that part is the
easy half — it's triage: a deterministic 7-factor scoring engine, an
optional and structurally powerless AI layer, and a human-gated verification
lifecycle on top. Passive by default; active scanning needs three
independent authorizations to agree before it fires.
