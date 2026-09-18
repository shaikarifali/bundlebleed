from __future__ import annotations

import re

from bundlebleed.extractors.parameters import tokenize_identifier
from bundlebleed.hypotheses.models import Hypothesis
from bundlebleed.hypotheses.scoring import ConfidenceFactors, risk_for_confidence, score_confidence
from bundlebleed.identity import endpoint_id, stable_id
from bundlebleed.models import AIEndpointVerdict, ScanResult

_NUMERIC_ID_RE = re.compile(r"/\d+(?:/|$|\?)")
_NUMERIC_ID_QUERY_RE = re.compile(r"[?&]([a-zA-Z_][a-zA-Z0-9_\-]*)=\d+")
_PARAM_PATTERNS = {"express_style_param", "openapi_style_param"}
_SENSITIVE_PATH_RE = re.compile(r"\b(admin|internal|debug|private|staff)\b", re.I)
_TEMPLATE_PARAM_RE = re.compile(r"(:[a-zA-Z_][a-zA-Z0-9_]*|\{[a-zA-Z_][a-zA-Z0-9_]*\})")

_IDENTIFIER_RUN_RE = re.compile(r"[a-zA-Z_][a-zA-Z0-9_\-]*")
_SSRF_TIGHT_KEYWORDS = {"webhook", "callback", "proxy"}
_SSRF_URL_QUALIFIERS = {"target", "fetch", "source", "remote", "import", "external"}

# Sink names from dom_sinks.yaml that indicate a prototype-pollution-prone
# deep-merge call, not a DOM XSS sink — same co-occurrence mechanism,
# different (and historically well-documented) bug class.
_PROTOTYPE_POLLUTION_SINKS = {
    "lodash_merge",
    "lodash_merge_with",
    "lodash_defaults_deep",
    "lodash_zip_object_deep",
    "lodash_set",
    "jquery_extend_deep",
    "deepmerge_call",
    "merge_deep_call",
}
# Navigation sinks -- distinct from generic DOM XSS: the impact of an
# attacker-controlled value reaching these is redirecting the victim, not
# script execution. Real disclosed reports (e.g. OAuth redirect_uri open
# redirects) treat this as its own bug class.
_OPEN_REDIRECT_SINKS = {
    "location_href_assign",
    "location_assign",
    "location_replace",
    "window_open",
}
# A mutation whose name suggests it crosses an authorization/tenant
# boundary -- high risk. Any other named mutation is still a real,
# previously-unlisted state-changing capability, just a narrower blast
# radius by default -- medium, never low/info.
_SENSITIVE_MUTATION_NAME_RE = re.compile(
    r"(?i)delete|remove|admin|role|permission|export|grant|promote|impersonate|"
    r"transfer|refund|credit|disable|enable|verify|ban|suspend|reset|password"
)

# Concrete KeyHacks-style liveness checks, one per secret type this tool can
# confidently give an exact command for. This tool never runs these itself
# and never stores the raw credential (Invariant 7) -- these are drafted so
# a human can paste in the value from their own capture (Burp, browser
# devtools, ...) and run it themselves, exactly like the IDOR verification
# drafts. A read-only "who am I" / "list my account" endpoint was chosen for
# every entry here specifically to avoid any state-changing side effect.
_KEYHACKS_COMMANDS: dict[str, str] = {
    "aws_access_key": (
        "aws configure set aws_access_key_id <ACCESS_KEY_ID> --profile bb-check && "
        "aws configure set aws_secret_access_key <SECRET_KEY> --profile bb-check && "
        "aws sts get-caller-identity --profile bb-check"
    ),
    "aws_secret_key": (
        "aws configure set aws_access_key_id <ACCESS_KEY_ID> --profile bb-check && "
        "aws configure set aws_secret_access_key <SECRET_KEY> --profile bb-check && "
        "aws sts get-caller-identity --profile bb-check"
    ),
    "google_api_key": (
        'curl "https://maps.googleapis.com/maps/api/geocode/json?address=test&key=<KEY>" '
        "-- a valid key returns real geocode results, not REQUEST_DENIED"
    ),
    "stripe_live_key": "curl https://api.stripe.com/v1/charges -u <KEY>:",
    "stripe_test_key": "curl https://api.stripe.com/v1/charges -u <KEY>:",
    "github_token": 'curl -H "Authorization: token <TOKEN>" https://api.github.com/user',
    "github_fine_grained_pat": (
        'curl -H "Authorization: token <TOKEN>" https://api.github.com/user'
    ),
    "slack_token": 'curl -H "Authorization: Bearer <TOKEN>" https://slack.com/api/auth.test',
    "twilio_account_sid": (
        "curl -u <ACCOUNT_SID>:<AUTH_TOKEN> "
        "https://api.twilio.com/2010-04-01/Accounts/<ACCOUNT_SID>.json"
    ),
    "twilio_api_key_sid": (
        "curl -u <ACCOUNT_SID>:<AUTH_TOKEN> "
        "https://api.twilio.com/2010-04-01/Accounts/<ACCOUNT_SID>.json"
    ),
    "sendgrid_api_key": (
        'curl -H "Authorization: Bearer <KEY>" https://api.sendgrid.com/v3/scopes'
    ),
    "mailgun_api_key": 'curl -s --user "api:<KEY>" https://api.mailgun.net/v3/domains',
    "npm_token": (
        'curl -H "Authorization: Bearer <TOKEN>" https://registry.npmjs.org/-/npm/v1/user'
    ),
    "discord_bot_token": (
        'curl -H "Authorization: Bot <TOKEN>" https://discord.com/api/v10/users/@me'
    ),
    "square_access_token": (
        'curl -H "Authorization: Bearer <TOKEN>" https://connect.squareup.com/v2/locations'
    ),
    "azure_storage_account_key": (
        "az storage container list --account-name <ACCOUNT_NAME> --account-key <KEY>"
    ),
    "openai_api_key": 'curl https://api.openai.com/v1/models -H "Authorization: Bearer <KEY>"',
    "anthropic_api_key": (
        'curl https://api.anthropic.com/v1/models -H "x-api-key: <KEY>" '
        '-H "anthropic-version: 2023-06-01"'
    ),
    "anthropic_admin_api_key": (
        'curl https://api.anthropic.com/v1/organizations/users -H "x-api-key: <KEY>" '
        '-H "anthropic-version: 2023-06-01"'
    ),
    "huggingface_token": (
        'curl -H "Authorization: Bearer <TOKEN>" https://huggingface.co/api/whoami-v2'
    ),
    "cloudflare_api_token": (
        'curl -H "Authorization: Bearer <TOKEN>" '
        "https://api.cloudflare.com/client/v4/user/tokens/verify"
    ),
    "digitalocean_pat": (
        'curl -H "Authorization: Bearer <TOKEN>" https://api.digitalocean.com/v2/account'
    ),
    "gitlab_pat": 'curl --header "PRIVATE-TOKEN: <TOKEN>" https://gitlab.com/api/v4/user',
    "postman_api_key": 'curl -H "X-Api-Key: <KEY>" https://api.getpostman.com/me',
    "notion_api_token": (
        'curl -H "Authorization: Bearer <TOKEN>" -H "Notion-Version: 2022-06-28" '
        "https://api.notion.com/v1/users/me"
    ),
    "sentry_org_auth_token": (
        'curl -H "Authorization: Bearer <TOKEN>" https://sentry.io/api/0/organizations/'
    ),
    "supabase_management_pat": (
        'curl -H "Authorization: Bearer <TOKEN>" https://api.supabase.com/v1/projects'
    ),
    "heroku_api_key_v2": (
        'curl -H "Authorization: Bearer <TOKEN>" '
        '-H "Accept: application/vnd.heroku+json; version=3" '
        "https://api.heroku.com/account"
    ),
    "posthog_personal_api_key": (
        'curl -H "Authorization: Bearer <TOKEN>" https://app.posthog.com/api/users/@me/'
    ),
    "cohere_api_token": ('curl https://api.cohere.ai/v1/models -H "Authorization: Bearer <TOKEN>"'),
    "clerk_secret_key": 'curl -H "Authorization: Bearer <KEY>" https://api.clerk.com/v1/users',
}


def _has_numeric_id_query_param(value: str) -> bool:
    """True for a query string like '?productId=1' or '?user_id=5' — a
    caller-supplied numeric id, just not in the URL path. Uses the same
    word-boundary tokenizer as parameter extraction so 'valid=1'/'void=1'
    don't false-positive on the raw substring 'id'."""
    return any("id" in tokenize_identifier(key) for key in _NUMERIC_ID_QUERY_RE.findall(value))


def _has_ssrf_shape(value: str) -> bool:
    """True for a caller-controlled path segment or query parameter that
    looks like it hands a URL to the server to fetch server-side — SSRF,
    one of the highest-payout bug classes in real-world bounty reports
    (often escalating to cloud-metadata credential theft). Word-boundary
    tokenized so 'profileUrl'/'avatarUrl' don't false-positive on the bare
    substring 'url'."""
    for candidate in _IDENTIFIER_RUN_RE.findall(value):
        tokens = set(tokenize_identifier(candidate))
        if tokens & _SSRF_TIGHT_KEYWORDS:
            return True
        if {"url", "uri"} & tokens and tokens & (_SSRF_URL_QUALIFIERS | _SSRF_TIGHT_KEYWORDS):
            return True
    return False


def _endpoint_template_regex(value: str) -> re.Pattern[str]:
    """Turn ':id'/'{id}'-style path templates into a matchable regex."""
    parts: list[str] = []
    last = 0
    for m in _TEMPLATE_PARAM_RE.finditer(value):
        parts.append(re.escape(value[last : m.start()]))
        parts.append(r"[^/]+")
        last = m.end()
    parts.append(re.escape(value[last:]))
    return re.compile("^" + "".join(parts) + "$")


def _runtime_confirms(endpoint_value: str, runtime_paths: set[str]) -> bool:
    """True if the running page actually requested this endpoint — either
    literally, or (for a templated path like '/users/:id') a runtime
    request matching the template shape."""
    if endpoint_value in runtime_paths:
        return True
    if not _TEMPLATE_PARAM_RE.search(endpoint_value):
        return False
    pattern = _endpoint_template_regex(endpoint_value)
    return any(pattern.match(path) for path in runtime_paths)


def _ai_verdict_for(
    endpoint_id_: str, ai_verdicts: list[AIEndpointVerdict]
) -> AIEndpointVerdict | None:
    for verdict in ai_verdicts:
        if verdict.evidence_id == endpoint_id_:
            return verdict
    return None


def generate_hypotheses(result: ScanResult) -> list[Hypothesis]:
    """Turn flat findings into explainable, scored hypotheses.

    Only endpoints matching a known vulnerability *shape* (caller-supplied
    id, sensitive path segment) generate an endpoint hypothesis — an
    ordinary endpoint with no suspicious signal isn't hypothesis-worthy on
    its own. Every secret and DOM finding always does, since those are
    already narrow, high-signal detections.
    """
    hypotheses: list[Hypothesis] = []
    js_body_only_values = set(
        result.endpoint_schema_discrepancy.js_body_only
        if result.endpoint_schema_discrepancy
        else []
    )
    auth_only_urls = set(result.auth_only_js_urls)
    historical_values = set(result.historical_endpoint_values)
    runtime_paths = set(result.runtime_confirmed_paths)

    for endpoint in result.endpoints:
        eid = endpoint_id(endpoint)
        bug_classes: list[str] = []
        evidence_chain = [
            f"Endpoint discovered via pattern '{endpoint.pattern_name}' at {endpoint.source_url}"
        ]
        if endpoint.also_seen_in:
            evidence_chain.append(
                f"Also referenced from {len(endpoint.also_seen_in)} other file(s): "
                + ", ".join(endpoint.also_seen_in)
            )

        rule_match = False
        if (
            _NUMERIC_ID_RE.search(endpoint.value)
            or _has_numeric_id_query_param(endpoint.value)
            or endpoint.pattern_name in _PARAM_PATTERNS
        ):
            bug_classes.append("IDOR")
            rule_match = True
            evidence_chain.append(
                "Path or query string contains a caller-influenceable identifier "
                "(numeric id, id-like query parameter, or route parameter)"
            )
        if _SENSITIVE_PATH_RE.search(endpoint.value):
            bug_classes.append("Broken Function-Level Authorization")
            rule_match = True
            evidence_chain.append(
                "Path contains a sensitive-looking segment (admin/internal/debug/private/staff)"
            )
        if _has_ssrf_shape(endpoint.value):
            bug_classes.append("SSRF")
            rule_match = True
            evidence_chain.append(
                "Path segment or query parameter name suggests the server fetches a "
                "caller-supplied URL server-side (webhook/callback/proxy/target URL shape)"
            )

        if not rule_match:
            continue

        ai_verdict = _ai_verdict_for(eid, result.ai_verdicts)
        ai_confidence = None
        if ai_verdict is not None:
            for bug_class in ai_verdict.bug_classes:
                if bug_class not in bug_classes:
                    bug_classes.append(bug_class)
            ai_confidence = ai_verdict.confidence
            evidence_chain.append(
                f"AI classified this endpoint as {', '.join(ai_verdict.bug_classes)} "
                f"with confidence {ai_verdict.confidence:.2f} (model={ai_verdict.model}, "
                f"prompt_version={ai_verdict.prompt_version})"
            )

        js_body_only = endpoint.value in js_body_only_values
        if js_body_only:
            evidence_chain.append(
                "Only visible after downloading the JS body — not discoverable from the "
                "collected URL string alone"
            )

        auth_context = endpoint.source_url in auth_only_urls
        if auth_context:
            evidence_chain.append(
                "Only visible in a JS bundle reachable with an authenticated session — "
                "not present in the unauthenticated crawl"
            )

        historical_match = endpoint.value in historical_values
        if historical_match:
            evidence_chain.append(
                "Also present in a previous scan of this target — not a one-off artifact"
            )

        runtime_evidence = _runtime_confirms(endpoint.value, runtime_paths)
        if runtime_evidence:
            evidence_chain.append(
                "Confirmed at runtime — the running page actually requested this endpoint, "
                "not just a string found in JS source"
            )

        confidence = score_confidence(
            ConfidenceFactors(
                static_pattern_match=True,
                js_body_only=js_body_only,
                rule_pattern_match=rule_match,
                auth_context=auth_context,
                historical_match=historical_match,
                runtime_evidence=runtime_evidence,
                ai_confidence=ai_confidence,
            )
        )

        if ai_verdict is not None:
            proposed_test = ai_verdict.test_plan
        elif "SSRF" in bug_classes:
            proposed_test = (
                "Manually supply a URL you control (e.g. a request-bin) as the value and "
                "confirm the server actually makes an outbound request to it before "
                "considering cloud-metadata or internal-host targets — only within your "
                "engagement's authorized scope."
            )
        else:
            proposed_test = (
                "Manually review this endpoint for missing server-side authorization: "
                "compare responses across two low-privilege accounts / two object ids."
            )

        hypotheses.append(
            Hypothesis(
                id=eid,
                target_kind="endpoint",
                target_value=endpoint.value,
                source_url=endpoint.source_url,
                bug_classes=bug_classes,
                evidence_chain=evidence_chain,
                confidence=confidence,
                risk=risk_for_confidence(confidence),
                proposed_test=proposed_test,
            )
        )

    for secret in result.secrets:
        hid = stable_id("secret", secret.secret_type, secret.partial_hash, secret.source_url)
        if secret.secret_type == "jwt_alg_none":
            bug_classes = ["Authentication Bypass"]
            proposed_test = (
                "This JWT's header claims alg=none — if the server genuinely skips "
                "signature verification for it, this is a critical, direct auth-bypass "
                "primitive. Confirming exploitability requires a deliberate, authorized "
                "auth-bypass test outside this tool's automated scope: report immediately "
                "per your engagement's rules of engagement before any further testing."
            )
        elif secret.secret_type == "firebase_config":
            bug_classes = ["Misconfigured Cloud Database"]
            proposed_test = (
                "Manually issue a single read-only GET to "
                "https://<this-database>/.json (no auth header) and confirm whether the "
                "response is data or a permission-denied error — never attempt a write."
            )
        elif secret.secret_type == "graphql_introspection_reference":
            bug_classes = ["GraphQL Introspection Exposure"]
            proposed_test = (
                "Send a single, minimal introspection query (e.g. { __schema { queryType "
                "{ name } } }) to the GraphQL endpoint and confirm whether it responds with "
                "schema data instead of a disabled-introspection error — read-only, no "
                "mutation."
            )
        elif secret.secret_type == "cloud_storage_reference":
            bug_classes = ["Possible Subdomain/Bucket Takeover Candidate"]
            proposed_test = (
                "Passively resolve the bucket/hostname (DNS lookup, or a plain GET to the "
                "bucket's own listing/website endpoint) to confirm whether it still exists "
                "and is still owned by this target — never claim or write to it."
            )
        elif secret.secret_type == "cloud_metadata_reference":
            bug_classes = ["Cloud Metadata Endpoint Reference (possible SSRF target)"]
            proposed_test = (
                "This string only makes sense if some server-side route proxies a request "
                "to it — identify which endpoint embeds this value and treat it as a "
                "high-value SSRF target; do not query the metadata service directly "
                "yourself outside an authorized, scoped test of that endpoint."
            )
        elif secret.secret_type == "exposed_api_docs_path":
            bug_classes = ["Exposed API Documentation"]
            proposed_test = (
                "Issue a single read-only GET to this path and confirm whether it serves "
                "a live API spec — an accurate spec often reveals undocumented endpoints "
                "or parameters faster than blind recon."
            )
        elif secret.secret_type == "exposed_vcs_config_path":
            bug_classes = ["Exposed VCS/Config Path Reference"]
            proposed_test = (
                "Issue a single read-only GET to this path and confirm whether it serves "
                "real repository/config content rather than a 404 — a live .git/.env "
                "exposure can mean full source/credential disclosure."
            )
        elif secret.secret_type == "internal_hostname_reference":
            bug_classes = ["Internal Hostname Disclosure"]
            proposed_test = (
                "This is an information-disclosure lead, not a vulnerability by itself: "
                "confirm the hostname is genuinely non-public (not just a normal "
                "marketing subdomain) before treating it as in-scope internal "
                "infrastructure disclosure."
            )
        else:
            bug_classes = ["Hardcoded Credential Exposure"]
            keyhacks_command = _KEYHACKS_COMMANDS.get(secret.secret_type)
            if keyhacks_command is not None:
                proposed_test = (
                    "This tool never validates a credential itself. Using the full value "
                    "from your own capture (this tool never stores it), run:\n"
                    f"  {keyhacks_command}\n"
                    "A successful, non-error response means the credential is live; "
                    "determine scope of access before reporting. Only run this against a "
                    "credential you're authorized to test as part of your engagement."
                )
            else:
                proposed_test = (
                    "Verify whether this credential is live using the KeyHacks method for "
                    "its type; if live, determine scope of access before reporting. Only "
                    "run this against a credential you're authorized to test as part of "
                    "your engagement."
                )
        hypotheses.append(
            Hypothesis(
                id=hid,
                target_kind="secret",
                target_value=secret.redacted_value,
                source_url=secret.source_url,
                bug_classes=bug_classes,
                evidence_chain=[
                    f"Matched the '{secret.secret_type}' secret pattern at {secret.source_url}",
                    f"Pattern-assigned severity: {secret.severity}",
                ],
                confidence=score_confidence(ConfidenceFactors(static_pattern_match=True)),
                risk=secret.severity,
                proposed_test=proposed_test,
            )
        )

    for finding in result.dom_findings:
        hid = stable_id("dom", finding.sink_pattern, finding.source_url)
        confidence = min(0.3 + 0.1 * len(finding.co_occurring_sources), 0.6)
        is_proto_pollution = finding.sink_pattern in _PROTOTYPE_POLLUTION_SINKS
        is_open_redirect = finding.sink_pattern in _OPEN_REDIRECT_SINKS
        if is_proto_pollution:
            bug_class = "Prototype Pollution"
            proposed_test = (
                "Trace whether the co-occurring source reaches a key/path argument of "
                "this merge call unsanitized (e.g. via '__proto__'/'constructor.prototype'); "
                "only craft a non-destructive PoC (a benign added property, never a "
                "destructive one) after manual confirmation."
            )
        elif is_open_redirect:
            bug_class = "Open Redirect"
            proposed_test = (
                "Trace whether the co-occurring source (location.search/hash, "
                "document.referrer, or similar) reaches this navigation call "
                "unvalidated; if so, craft a URL pointing to a domain you control and "
                "confirm the victim's browser is actually redirected there. Especially "
                "high-impact if this redirect sits in an OAuth/SSO flow (redirect_uri, "
                "return_to, next) — chains directly to auth-code/token theft."
            )
        else:
            bug_class = "DOM XSS"
            proposed_test = (
                "Trace whether the co-occurring source actually flows into this sink "
                "without sanitization; only craft a non-destructive PoC after manual "
                "confirmation."
            )
        hypotheses.append(
            Hypothesis(
                id=hid,
                target_kind="dom_finding",
                target_value=finding.sink_value,
                source_url=finding.source_url,
                bug_classes=[bug_class],
                evidence_chain=[
                    f"Sink '{finding.sink_pattern}' co-occurs with source(s): "
                    f"{', '.join(finding.co_occurring_sources)}",
                    "Co-occurrence only — no data-flow tracing performed yet",
                ],
                confidence=confidence,
                risk=risk_for_confidence(confidence),
                proposed_test=proposed_test,
            )
        )

    for cors in result.cors_findings:
        hid = stable_id("cors", cors.source_url)
        hypotheses.append(
            Hypothesis(
                id=hid,
                target_kind="cors_misconfiguration",
                target_value=cors.source_url,
                source_url=cors.source_url,
                bug_classes=["CORS Misconfiguration"],
                evidence_chain=[
                    f"Response carried Access-Control-Allow-Origin: {cors.allow_origin} "
                    "together with Access-Control-Allow-Credentials: true",
                    "This combination is invalid per the Fetch spec (browsers reject it) — "
                    "a server sending both anyway is a real misconfiguration, not a guess",
                ],
                confidence=score_confidence(ConfidenceFactors(static_pattern_match=True)),
                risk="high",
                proposed_test=(
                    "Confirm with a real browser request from an attacker-controlled origin "
                    "whether credentialed cross-origin reads actually succeed against an "
                    "authenticated endpoint — read-only, no state-changing request."
                ),
            )
        )

    for subdomain in result.subdomains:
        if subdomain.in_scope:
            continue
        hid = stable_id("subdomain", subdomain.domain, subdomain.source_url)
        hypotheses.append(
            Hypothesis(
                id=hid,
                target_kind="subdomain",
                target_value=subdomain.domain,
                source_url=subdomain.source_url,
                bug_classes=["Scope Verification Needed"],
                evidence_chain=[
                    f"Referenced in JS at {subdomain.source_url}",
                    subdomain.note,
                ],
                confidence=0.2,
                risk="low",
                proposed_test=(
                    "Confirm with the program whether this subdomain is in scope before any "
                    "further testing."
                ),
            )
        )

    for script in result.third_party_scripts:
        hid = stable_id("third_party_script", script.hostname, script.script_url)
        hypotheses.append(
            Hypothesis(
                id=hid,
                target_kind="third_party_script",
                target_value=script.script_url,
                source_url=script.page_url,
                bug_classes=["Client-Side Supply Chain Surface"],
                evidence_chain=[
                    f"Loaded via <script src> on {script.page_url}",
                    f"Served from third-party host: {script.hostname}",
                ],
                confidence=0.2,
                risk="low",
                proposed_test=(
                    "Pure discovery, not a claim of compromise: note this third-party "
                    "dependency for a supply-chain review (e.g. is the host still owned by "
                    "the expected party, does it use Subresource Integrity)."
                ),
            )
        )

    for pm in result.postmessage_findings:
        hid = stable_id("postmessage", pm.source_url)
        hypotheses.append(
            Hypothesis(
                id=hid,
                target_kind="postmessage",
                target_value=pm.snippet_preview,
                source_url=pm.source_url,
                bug_classes=["PostMessage Missing Origin Check"],
                evidence_chain=[
                    f"A 'message' event listener is registered in {pm.source_url} with no "
                    "'.origin' check found anywhere else in the same file",
                    "Whole-file co-occurrence only — no data-flow tracing performed yet",
                ],
                confidence=0.3,
                risk="high",
                proposed_test=(
                    "From an attacker-controlled page, postMessage a benign, non-destructive "
                    "probe payload to this page and confirm whether the handler acts on it "
                    "regardless of sender origin."
                ),
            )
        )

    for ws in result.websocket_findings:
        hid = stable_id("websocket", ws.source_url, ws.snippet_preview)
        hypotheses.append(
            Hypothesis(
                id=hid,
                target_kind="websocket",
                target_value=ws.snippet_preview,
                source_url=ws.source_url,
                bug_classes=["Cross-Site WebSocket Hijacking Candidate"],
                evidence_chain=[
                    f"A WebSocket connection in {ws.source_url} has no visible token/auth "
                    "hint nearby — may rely on ambient cookie auth alone",
                ],
                confidence=0.25,
                risk="medium",
                proposed_test=(
                    "From a page on a different origin, attempt to open this WebSocket "
                    "connection relying only on the browser's ambient session cookie and "
                    "confirm whether the server accepts it without checking the Origin "
                    "header."
                ),
            )
        )

    for ma in result.mass_assignment_findings:
        hid = stable_id("mass_assignment", ma.source_url, ma.field_name)
        hypotheses.append(
            Hypothesis(
                id=hid,
                target_kind="mass_assignment",
                target_value=ma.field_name,
                source_url=ma.source_url,
                bug_classes=["Mass Assignment / Object Property Injection"],
                evidence_chain=[
                    f"Privileged-looking field '{ma.field_name}' is assigned inside an "
                    f"object literal near a PATCH/PUT/POST call in {ma.source_url}",
                ],
                confidence=0.3,
                risk=ma.severity,
                proposed_test=(
                    "Using a low-privilege controlled test account, send the real request "
                    "but add this field with a different, still-authorized value; if the "
                    "server applies it (e.g. escalates a role or crosses a tenant/owner "
                    "boundary), this is a confirmed mass-assignment vulnerability. Never "
                    "test with a genuinely destructive or unauthorized value."
                ),
            )
        )

    for lib in result.vulnerable_libraries:
        hid = stable_id(
            "vulnerable_library", lib.source_url, lib.library_name, lib.detected_version
        )
        hypotheses.append(
            Hypothesis(
                id=hid,
                target_kind="vulnerable_library",
                target_value=f"{lib.library_name} {lib.detected_version}",
                source_url=lib.source_url,
                bug_classes=["Known-Vulnerable JS Dependency"],
                evidence_chain=[
                    f"Detected {lib.library_name} {lib.detected_version} (vulnerable below "
                    f"{lib.vulnerable_below}) in {lib.source_url}",
                    f"{lib.cve}: {lib.description}",
                ],
                confidence=0.4,
                risk=lib.severity,
                proposed_test=(
                    "A vulnerable library version is not proof of an exploitable "
                    "application: confirm the specific vulnerable code path the CVE "
                    "describes is actually reachable and fed attacker-controlled input "
                    "before reporting."
                ),
            )
        )

    for op in result.graphql_operations:
        if op.operation_type != "mutation":
            # Queries/subscriptions are pure inventory (shown in reports)
            # -- not a finding on their own, so no hypothesis/severity.
            continue
        hid = stable_id("graphql_mutation", op.source_url, op.operation_name)
        is_sensitive = bool(_SENSITIVE_MUTATION_NAME_RE.search(op.operation_name))
        hypotheses.append(
            Hypothesis(
                id=hid,
                target_kind="graphql_mutation",
                target_value=op.operation_name,
                source_url=op.source_url,
                bug_classes=["GraphQL Mutation Exposed"],
                evidence_chain=[
                    f"Mutation '{op.operation_name}' found in {op.source_url}",
                ],
                confidence=0.3,
                risk="high" if is_sensitive else "medium",
                proposed_test=(
                    "Confirm this mutation is reachable from the GraphQL endpoint and "
                    "check its authorization: call it with a low-privilege authenticated "
                    "session and, separately, with no authentication at all. Do not "
                    "execute a state-changing call against real data without an "
                    "explicitly authorized, controlled account."
                ),
            )
        )

    for cname in result.dangling_cnames:
        hid = stable_id("dangling_cname", cname.domain)
        hypotheses.append(
            Hypothesis(
                id=hid,
                target_kind="dangling_cname",
                target_value=cname.domain,
                source_url=cname.domain,
                bug_classes=["Subdomain Takeover Candidate"],
                evidence_chain=[
                    f"{cname.domain} has a CNAME pointing to {cname.cname_target}, a "
                    f"'{cname.service_hint}' service with a documented history of "
                    "unclaimed-record takeover",
                    "DNS resolution only -- this tool never contacted the CNAME target",
                ],
                confidence=0.3,
                risk="high",
                proposed_test=(
                    f"Check whether {cname.cname_target} is actually unclaimed: use the "
                    f"provider's own UI/CLI for '{cname.service_hint}' to check name "
                    "availability, or fetch the URL yourself and look for that service's "
                    "known 'no such app'/'bucket does not exist' page. Never attempt to "
                    "claim the resource without explicit authorization from the program "
                    "AND, in most cases, the service provider's own terms."
                ),
            )
        )

    return hypotheses
