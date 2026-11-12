from __future__ import annotations

import re

from bundlebleed.extractors.parameters import tokenize_identifier
from bundlebleed.hypotheses.models import Hypothesis
from bundlebleed.hypotheses.scoring import ConfidenceFactors, risk_for_confidence, score_confidence
from bundlebleed.identity import endpoint_id, stable_id
from bundlebleed.models import AIEndpointVerdict, ScanResult

# Auth finding types that map directly to bug classes
_AUTH_FINDING_BUG_CLASSES: dict[str, tuple[str, str, str]] = {
    # (bug_class, risk, proposed_test)
    "jwt_alg_none": (
        "Authentication Bypass",
        "critical",
        "The JWT header declares alg=none — if the server accepts it without verification "
        "this is a direct authentication bypass. Confirm manually using an authorisation "
        "token you legitimately hold, stripped of its signature; never test against accounts "
        "you do not own.",
    ),
    "jwt_decode_no_verify": (
        "Authentication Bypass",
        "high",
        "JWT is decoded without signature verification — the app may trust attacker-controlled "
        "claims. Manually test with a modified claim (e.g. elevated role) signed with a "
        "throwaway key to confirm whether the server rejects it.",
    ),
    "jwt_jku_x5u": (
        "Authentication Bypass",
        "high",
        "The JWT references an external key-set URL (jku/x5u) — a classic JWKS injection "
        "vector. Confirm whether the server fetches the URL and trusts arbitrary keys by "
        "providing a self-hosted JWKS in a manual test.",
    ),
    "token_in_local_storage": (
        "Session Token Exposure",
        "medium",
        "Authentication token stored in localStorage is accessible to any same-origin JS. "
        "Assess whether an XSS on the same origin would allow token theft; report if a "
        "credible XSS vector already exists.",
    ),
    "oauth_implicit_flow": (
        "OAuth Implicit Flow",
        "medium",
        "Implicit flow exposes the access token in the URL fragment. Confirm whether "
        "referrer headers, browser history, or postMessage forwarding can leak it.",
    ),
    "oauth_missing_state": (
        "CSRF on OAuth Flow",
        "medium",
        "OAuth flow lacks a state parameter — susceptible to CSRF that forces a victim "
        "to link their account to an attacker-controlled OAuth identity.",
    ),
    "oauth_missing_pkce": (
        "OAuth Code Interception",
        "medium",
        "Public client OAuth flow without PKCE — an authorisation code stolen in transit "
        "can be exchanged for tokens. Confirm the token endpoint also does not enforce PKCE.",
    ),
    "dynamic_redirect_uri": (
        "Open Redirect / Token Leakage via redirect_uri",
        "medium",
        "The redirect_uri is constructed dynamically from attacker-influenced input. "
        "Confirm whether the authorisation server validates it strictly or allows an "
        "attacker-supplied domain.",
    ),
}

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
        else:
            bug_classes = ["Hardcoded Credential Exposure"]
            proposed_test = (
                "Verify whether this credential is live using the KeyHacks method for "
                "its type; if live, determine scope of access before reporting."
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
        if is_proto_pollution:
            bug_class = "Prototype Pollution"
            proposed_test = (
                "Trace whether the co-occurring source reaches a key/path argument of "
                "this merge call unsanitized (e.g. via '__proto__'/'constructor.prototype'); "
                "only craft a non-destructive PoC (a benign added property, never a "
                "destructive one) after manual confirmation."
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

    # --- R3: DOM taint findings (proximity-based source → sink chains) ---
    seen_dom_taint: set[str] = set()
    for dt in result.dom_taint_findings:
        hid = stable_id("dom_taint", dt.source_name, dt.sink_name, dt.source_url, str(dt.sink_line))
        if hid in seen_dom_taint:
            continue
        seen_dom_taint.add(hid)
        if dt.sink_category == "open_redirect":
            bug_class = "Open Redirect"
            risk = "medium"
            proposed_test = (
                "Confirm whether the user-controlled source actually reaches the redirect "
                "sink without server-side whitelist validation — manually supply an "
                "attacker-controlled URL and check if the browser follows it."
            )
        elif dt.sink_category in ("code_exec", "script_injection"):
            bug_class = "DOM XSS / Code Execution"
            risk = "high"
            proposed_test = (
                "Trace whether the source flows into the sink without sanitization; "
                "craft a minimal non-destructive PoC (alert(1)) only after manual "
                "confirmation of the data-flow path — proximity analysis is not proof."
            )
        else:
            bug_class = "DOM XSS"
            risk = "high"
            proposed_test = (
                "Verify the data-flow path: does the source value reach the sink "
                "unsanitized? Proximity analysis found them within 35 lines but cannot "
                "confirm actual taint — trace manually before crafting any PoC."
            )
        bridge_note = (
            f" Variable bridge: '{dt.variable_bridge}'."
            if getattr(dt, "variable_bridge", None)
            else ""
        )
        hypotheses.append(
            Hypothesis(
                id=hid,
                target_kind="dom_taint",
                target_value=f"{dt.source_name} → {dt.sink_name}",
                source_url=dt.source_url,
                bug_classes=[bug_class],
                evidence_chain=[
                    f"Source '{dt.source_name}' (line {dt.source_line}) co-occurs with "
                    f"sink '{dt.sink_name}' (line {dt.sink_line}) within 35 lines.{bridge_note}",
                    f"Sink category: {dt.sink_category}",
                    "Proximity analysis only — not a proven data-flow path",
                ],
                confidence=0.45,
                risk=risk,
                proposed_test=proposed_test,
            )
        )

    # --- R3: Prototype pollution findings ---
    seen_proto: set[str] = set()
    for pp in result.proto_pollution_findings:
        hid = stable_id("proto_pollution", pp.pattern_name, pp.source_url, str(pp.line))
        if hid in seen_proto:
            continue
        seen_proto.add(hid)
        # L5 (Object.prototype direct) is highest impact; L1 (__proto__) is still critical
        confidence = min(0.35 + pp.level * 0.1, 0.85)
        risk = "high" if pp.level >= 3 else "medium"
        hypotheses.append(
            Hypothesis(
                id=hid,
                target_kind="proto_pollution",
                target_value=pp.pattern_name,
                source_url=pp.source_url,
                bug_classes=["Prototype Pollution"],
                evidence_chain=[
                    f"[L{pp.level}] {pp.detail} at line {pp.line} in {pp.file}",
                    "Gadgets detected" if getattr(pp, "gadgets", None) else "No gadgets detected in same file",
                ],
                confidence=confidence,
                risk=risk,
                proposed_test=(
                    "Confirm whether attacker-controlled input reaches the polluting "
                    "assignment (e.g. via URL params, JSON body); craft a minimal PoC "
                    "that sets a benign property (e.g. '__proto__.x=1') and verifies it "
                    "propagates — never use a destructive property."
                ),
            )
        )

    # --- R2: Auth configuration findings ---
    seen_auth: set[str] = set()
    for af in result.auth_findings:
        hid = stable_id("auth_finding", af.finding_type, af.source_url, str(af.line))
        if hid in seen_auth:
            continue
        seen_auth.add(hid)
        mapping = _AUTH_FINDING_BUG_CLASSES.get(af.finding_type)
        if mapping is None:
            continue
        bug_class, risk, proposed_test = mapping
        hypotheses.append(
            Hypothesis(
                id=hid,
                target_kind="auth_finding",
                target_value=af.finding_type,
                source_url=af.source_url,
                bug_classes=[bug_class],
                evidence_chain=[
                    f"Pattern '{af.finding_type}' matched at line {af.line} in {af.file}",
                    f"Detail: {af.detail}",
                    f"Severity candidate: {af.severity_candidate}",
                ],
                confidence=0.55 if af.severity_candidate in ("critical", "high") else 0.35,
                risk=risk,
                proposed_test=proposed_test,
            )
        )

    # --- R3: postMessage findings (wildcard origin senders + unsanitized receivers) ---
    seen_pm: set[str] = set()
    for pm in result.postmessage_findings:
        hid = stable_id("postmessage", pm.kind, pm.source_url, str(pm.line))
        if hid in seen_pm:
            continue
        seen_pm.add(hid)
        if pm.kind == "sender" and pm.target_origin == "*":
            hypotheses.append(
                Hypothesis(
                    id=hid,
                    target_kind="postmessage",
                    target_value="postMessage sender with wildcard origin",
                    source_url=pm.source_url,
                    bug_classes=["postMessage Data Exposure"],
                    evidence_chain=[
                        f"postMessage() called with targetOrigin='*' at line {pm.line} — "
                        "any page can receive this message regardless of origin",
                    ],
                    confidence=0.4,
                    risk="medium",
                    proposed_test=(
                        "Confirm whether the message payload contains sensitive data "
                        "(tokens, PII, internal state); if so, any cross-origin frame "
                        "can intercept it."
                    ),
                )
            )
        elif pm.kind == "receiver" and not pm.has_origin_check and pm.data_sinks:
            hypotheses.append(
                Hypothesis(
                    id=hid,
                    target_kind="postmessage",
                    target_value="postMessage receiver without origin check",
                    source_url=pm.source_url,
                    bug_classes=["postMessage Injection"],
                    evidence_chain=[
                        f"addEventListener('message') at line {pm.line} does not validate "
                        f"event.origin before passing data to sink(s): {', '.join(pm.data_sinks)}",
                    ],
                    confidence=0.5,
                    risk="high",
                    proposed_test=(
                        "Confirm that an attacker-controlled page can send a crafted message "
                        "that reaches the sink unsanitized; craft a non-destructive PoC "
                        "(e.g. alert(1) via innerHTML) only after confirming the data-flow."
                    ),
                )
            )

    # --- R2: WebSocket findings (auth in URL, missing origin check) ---
    seen_ws: set[str] = set()
    for ws in result.websocket_findings:
        if ws.auth_in_url:
            hid = stable_id("ws_auth_url", ws.endpoint, ws.source_url, str(ws.line))
            if hid not in seen_ws:
                seen_ws.add(hid)
                hypotheses.append(
                    Hypothesis(
                        id=hid,
                        target_kind="websocket",
                        target_value=ws.endpoint,
                        source_url=ws.source_url,
                        bug_classes=["Credential Exposure in WebSocket URL"],
                        evidence_chain=[
                            f"WebSocket connection to '{ws.endpoint}' carries authentication "
                            f"token in the URL — visible in server access logs, browser history, "
                            f"and referrer headers.",
                        ],
                        confidence=0.5,
                        risk="medium",
                        proposed_test=(
                            "Confirm the token is a live credential and assess what it grants; "
                            "report if the token appears in server logs or is accessible to "
                            "intermediary infrastructure."
                        ),
                    )
                )

    return hypotheses
