# FAQ

## Isn't this just LinkFinder / GAP / nuclei with extra steps?

Those tools find candidate strings or run templates. BundleBleed wraps some
of that same discovery (`gau`, `waybackurls`, `waymore`, `paramspider`,
`katana`) but its actual job starts *after* discovery: score, attribute,
and route — turning hundreds of raw candidates into a handful worth
testing, with a citation-checked AI layer and a human-gated verification
lifecycle on top. It's a triage layer, not a competing discovery tool.

## Does the AI send my target's data somewhere?

The whole pipeline works with zero API keys — AI is opt-in
(`--ai`/`ai report`/`ai chains`). When it's on, it's provider-agnostic
(Anthropic, OpenRouter, or a fully local Ollama host), the model is always
explicitly pinned via `--model`, and it only ever receives
`pattern_name`/`value`/`source_url` — never secrets, raw JS bodies, or
severity values. See [How It Works § The AI layer](02-how-it-works.md#the-ai-layer).

## Can it exploit anything automatically?

No, structurally. No credential submission, no fuzzing, no brute-forcing,
no writes to a target anywhere in the codebase. `--draft-verification`
drafts a test as `.http`/`curl` artifacts; a human runs it and records the
outcome with `verify record`.

## What about false positives on secrets?

Obvious placeholders ("example," "dummy," "changeme," ...) are dropped
before they're even hashed. Known-tricky cases are handled explicitly —
PostHog's public project key is never flagged (only the private personal
key format), Algolia's public search key is never flagged (only the admin
key, gated on the word "admin" appearing nearby). A lone secret match
doesn't become a "critical" hypothesis by itself either — `jwt_alg_none`,
`firebase_config`, and `graphql_introspection_reference` each get their
own tailored, lower-noise handling rather than one generic "secret found"
bucket. Full list: [Detection Reference](03-detection-reference.md).

## Is this legal to run against a target?

Passive collection is on by default. Active scanning (`katana`,
`--runtime-capture`, `--draft-verification`, `--check-subdomain-takeover`)
each require three independent things to all be true at once: an
app-level config flag, a CLI flag, and a signed authorization attestation
in `scope.yaml`. It's built for scanning infrastructure you're authorized
to test — it enforces the scope you give it, but it cannot know whether
that scope is actually authorized. That's on you.

## Does it work on server-rendered apps, or only SPAs?

It works on whatever JavaScript the target ships, regardless of rendering
strategy — a server-rendered app with a smaller JS footprint will simply
surface fewer candidates. `extract_html_endpoints()` also pulls plain
`<a href>`/`<form action>` routes straight out of the HTML, which JS-only
patterns never see. Runtime capture specifically helps with
client-side-routed SPAs where a chunk only loads after a client-side
navigation or an auth state change.

## Why does the same endpoint sometimes show up with `also_seen_in` populated?

Because it was found in more than one file — a shared webpack chunk, or
the same literal string seen in both the raw-URL and JS-body extraction
passes. `deduplicate_endpoints()` merges these into one `Hypothesis`
instead of producing a duplicate per file, and keeps every other file it
appeared in as evidence rather than dropping it. See
[Architecture § Key internals](04-architecture.md#key-internals).

## Why is `Endpoint.method` sometimes `null`?

Because the pattern that matched it doesn't unambiguously name the HTTP
verb in the matched text. `fetch()`, bare `axios()`, and `$.ajax()` all
default to GET only when no options object overrides it — asserting "GET"
there would be a guess, not something the source text actually says. Full
table of which patterns do/don't capture a method:
[Detection Reference](03-detection-reference.md#endpoint-discovery--13-named-patterns).

## What's the license / can my company use this commercially?

MIT. No API key requirement, no paid tier gating any capability.

## How do I add my own detection pattern?

If it's an endpoint pattern, secret pattern, DOM sink/source, or
vulnerable-library fingerprint, it's a YAML edit — no code change needed.
See [Architecture § Adding a detection pattern](04-architecture.md#adding-a-detection-pattern--no-python-required).
