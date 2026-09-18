# Detection Reference

The exhaustive list. If someone asks "does it catch X," this is the page to
check before answering from memory.

## Endpoint discovery — 13 named patterns

| Pattern | What it catches | Method captured? |
|---|---|---|
| `rest_api_path` | `/api/...` and the internal-gateway convention `/api-internal/`, `/api-int/`, `/api-private/` | No |
| `express_style_param` | `/users/:id` style route templates | No |
| `openapi_style_param` | `/users/{id}` style route templates | No |
| `fetch_call` | `fetch('...')` literal URLs | No — see note below |
| `axios_call` | `axios.get/post/put/patch/delete(...)` | **Yes**, from the verb itself |
| `axios_shorthand` | `axios('...')` | No |
| `axios_config_object` | `axios({url: '...'})` | No |
| `jquery_ajax` | `$.ajax({url: '...'})` | No |
| `jquery_get_post` | `$.get(...)`, `$.post(...)` | **Yes**, from the verb itself |
| `xhr_open` | `XMLHttpRequest.open(METHOD, url)` | **Yes**, from the literal method argument |
| `send_beacon` | `navigator.sendBeacon(url)` | **Yes**, always `POST` (fixed by the Beacon API spec) |
| `graphql_endpoint` | `/graphql` or `/api/graphql` style paths | No |
| `websocket_url` | `ws://`/`wss://` literal URLs | No |

**Why some patterns don't get a method:** `Endpoint.method` is only
populated when the matched text itself unambiguously names the HTTP verb.
`fetch()`, bare `axios()`, and `$.ajax()` all default to GET only when no
options object overrides it — since the pattern's own regex doesn't parse
that options object, asserting "GET" would be a guess dressed up as a fact.
None of the ambiguous patterns assert a method; they leave it `null`.

HTML pages get two more sources the JS patterns don't cover:
`html_link` (`<a href>`, method `GET`) and `html_form_get`/`html_form_post`
(`<form action method="...">`) from `extractors/html_links.py`.

### Cross-file deduplication

The same endpoint referenced from more than one file — a shared webpack
chunk, or the same literal seen in both the raw-URL and JS-body extraction
passes — is merged into a single `Endpoint`, keyed on
`(pattern_name, value, method)`. The first file it was seen in becomes the
primary `source_url`; every other file it also appeared in is kept in
`also_seen_in` rather than silently dropped, and shows up as an extra line
in the resulting hypothesis's evidence chain
(`extractors/endpoints.py::deduplicate_endpoints`).

## Secrets & disclosure leads — 57 named patterns

Every match returns only *type*, a *redacted preview* (first 4 + last 4
characters, middle masked), and a *SHA-256 partial hash* (first 12 hex
chars) for dedup/correlation — never the raw value. A match inside an
obvious placeholder context ("example," "dummy," "changeme," ...) is
dropped before it's even hashed.

| Category | Patterns |
|---|---|
| Cloud / infra | `aws_access_key`, `aws_secret_key`, `gcp_service_account_key`, `azure_storage_account_key`, `cloudflare_global_api_key`, `cloudflare_api_token`, `digitalocean_pat`, `heroku_api_key_v2` |
| Payments | `stripe_live_key`, `stripe_test_key`, `square_access_token`, `square_oauth_secret`, `shopify_access_token`, `paypal_braintree_access_token` |
| Comms / SaaS | `slack_token`, `slack_webhook_url`, `twilio_account_sid`, `twilio_api_key_sid`, `sendgrid_api_key`, `mailgun_api_key`, `discord_webhook`, `discord_bot_token`, `mapbox_token` |
| Dev / VCS | `github_token`, `github_fine_grained_pat`, `gitlab_pat`, `npm_token`, `postman_api_key`, `notion_api_token`, `algolia_admin_api_key` |
| AI providers | `openai_api_key`, `anthropic_api_key`, `anthropic_admin_api_key`, `huggingface_token`, `cohere_api_token` |
| Backend-as-a-service | `firebase_config`, `supabase_management_pat`, `supabase_secret_key`, `clerk_secret_key`, `planetscale_token`, `posthog_personal_api_key` |
| Observability | `sentry_org_auth_token` |
| Auth / generic tokens | `jwt_token`, `jwt_alg_none` (critical — see below), `basic_auth_header`, `generic_bearer_token`, `generic_api_key_assignment`, `hardcoded_password` |
| Key material | `private_key_block`, `pgp_private_key_block` |
| Recon / disclosure leads | `graphql_introspection_reference`, `cloud_storage_reference`, `cloud_metadata_reference`, `exposed_api_docs_path`, `exposed_vcs_config_path`, `internal_hostname_reference`, `internal_ip` |

**`jwt_alg_none`:** every matched JWT additionally gets its header segment
base64-decoded at rest (no network call). If the header claims
`"alg":"none"`, that's reported as its own critical-severity finding,
distinct from a plain token leak — it's a direct signature-bypass
primitive, not just an exposed credential.

**Known false-positive avoidance built in:**
- `posthog_personal_api_key` only matches PostHog's *personal* key format
  (`phx_`) — never the intentionally-public project key (`phc_`) every
  PostHog-instrumented site ships by design.
- `algolia_admin_api_key` only fires when "admin" appears near the key —
  Algolia's public search-only key has the identical 32-char shape.
- `stripe_test_key` still fires on keys literally labeled "test" —
  filtering that word out would defeat the pattern's entire purpose.
- `internal_hostname_reference`'s lookbehind allows `.` and `-`
  immediately before the keyword (so `app.internal.example.com` and
  `api-internal.example.com` both match), while still rejecting a keyword
  glued onto a longer word with no separator (`devops.example.com`,
  `development.example.com`).

## Bug classes

14 total, derived from three different mechanisms:

| Bug class | Derived from |
|---|---|
| IDOR | Numeric or id-like query parameter in an endpoint path |
| Broken Function-Level Authorization | `admin`/`internal`/`debug`/`private`/`staff` in an endpoint path |
| SSRF | `webhook`/`callback`/`proxy` param name + `target`/`fetch`/`source`/`remote`/`import`/`external` qualifier |
| Authentication Bypass | `secret_type == jwt_alg_none` |
| Misconfigured Cloud Database | `secret_type == firebase_config` |
| GraphQL Introspection Exposure | `secret_type == graphql_introspection_reference` |
| GraphQL Mutation Exposed | Any extracted mutation operation; a sensitive-sounding name (delete/admin/role/grant/impersonate/...) scores high, others medium |
| Possible Subdomain/Bucket Takeover Candidate | `secret_type == cloud_storage_reference`, or a subdomain's CNAME matching a takeover-prone suffix |
| Cloud Metadata Endpoint Reference (possible SSRF target) | `secret_type == cloud_metadata_reference` |
| Exposed API Documentation | `secret_type == exposed_api_docs_path` |
| Exposed VCS/Config Path Reference | `secret_type == exposed_vcs_config_path` (`.git`/`.env` style) |
| Internal Hostname Disclosure | `secret_type == internal_hostname_reference` |
| Prototype Pollution | A DOM sink from the lodash/jQuery/deepmerge "deep merge" family co-occurring with a tainted source |
| Open Redirect | `location.href`/`.assign`/`.replace` or `window.open` co-occurring with a tainted source |
| Hardcoded Credential Exposure | Any other secret pattern match, with a KeyHacks-style liveness-check command drafted where one exists |

## DOM analysis — co-occurrence, not proven taint

Whole-file heuristic: if any of 9 tainted **sources** appear anywhere in a
file, every dangerous **sink** found in that same file is reported as a
candidate, with the co-occurring sources attached as evidence. Explicitly a
lead, not a proven data flow.

**Sources (9):** `location.hash`, `location.search`, `location.href`,
`document.referrer`, `window.name`, `document.cookie` (read), postMessage
event data, `localStorage.getItem`, `sessionStorage.getItem`.

**Sinks (20):** `document.write`, `innerHTML`, `outerHTML`, `eval()`,
`Function()`, `setTimeout`/`setInterval` with a string, `location.href`/
`.assign`/`.replace`, `window.open` (→ Open Redirect class),
`document.cookie` (write), lodash `merge`/`mergeWith`/`defaultsDeep`/
`zipObjectDeep`/`set`, `jQuery.extend(true, ...)`, `deepmerge()`,
`mergeDeep()` (→ Prototype Pollution class).

## Other extractors

| Extractor | What it does |
|---|---|
| GraphQL operations | Regex inventory of named query/mutation/subscription operations from graphql-tag/Apollo/Relay-style template literals — a lightweight inventory, not a schema parser |
| CORS misconfiguration | Flags only the one spec-invalid, unambiguous case: `Access-Control-Allow-Origin: *` combined with `Access-Control-Allow-Credentials: true`. No probe Origin header is ever sent |
| Mass assignment | Flags `role`/`isAdmin`/`organizationId`/`ownerId`/etc. sitting within 200 characters of a PATCH/PUT/POST call, filtered against ~70 ARIA role values so `role:"button"` in JSX never fires |
| Vulnerable libraries | Retire.js-style version-banner matching against 7 libraries with known CVEs (table below) |
| Subdomain takeover | Resolves each discovered subdomain's CNAME and checks it against 30 takeover-prone service suffixes. DNS-only — never an HTTP probe to the claim target itself |
| postMessage | Flags a `message` event listener with no `.origin` check anywhere in the same file |
| WebSocket | Flags `new WebSocket(...)` with no visible token/auth hint in the ~200 characters after it — a Cross-Site WebSocket Hijacking candidate |
| Framework detection | Signature matching for React, Angular, Vue, Next.js, Nuxt — informational context, not a finding |

### Vulnerable library CVEs

| Library | Vulnerable below | CVE(s) |
|---|---|---|
| jQuery | 3.5.0 | CVE-2020-11022, CVE-2020-11023 |
| Lodash | 4.17.21 | CVE-2020-8203, CVE-2021-23337 |
| Moment.js | 2.29.4 | CVE-2022-31129 |
| AngularJS | 1.8.0 | CVE-2020-7676 |
| Handlebars | 4.7.7 | CVE-2021-23369, CVE-2021-23383 |
| Bootstrap | 4.3.2 | CVE-2019-8331 |
| jQuery UI | 1.13.0 | CVE-2021-41182, -41183, -41184 |

Works because Terser/UglifyJS preserve `/*! ... */` banner comments by
default — a build that strips them produces a false negative here, never a
false positive.

Next: [04 — Architecture & Extending](04-architecture.md) for how to add
your own pattern to any of the tables above.
