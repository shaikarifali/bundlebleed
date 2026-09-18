from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from bundlebleed.history.models import ScanDiff
from bundlebleed.hypotheses.models import Hypothesis


class Endpoint(BaseModel):
    value: str
    pattern_name: str
    source_url: str
    # Only set when the matched text itself unambiguously names the HTTP
    # method (an axios/jquery verb call, a literal xhr.open() method
    # argument, an html <form method="...">, or sendBeacon's fixed POST) --
    # never guessed as a default for a call shape that could be either
    # (fetch(), bare axios(), $.ajax()), since that would assert something
    # the source text doesn't actually say.
    method: str | None = None
    # Populated by deduplicate_endpoints() when the identical
    # (pattern_name, value, method) triple was also seen in another file --
    # every occurrence is kept as evidence instead of silently dropped, but
    # only one Endpoint/Hypothesis represents it.
    also_seen_in: list[str] = Field(default_factory=list)


class Secret(BaseModel):
    secret_type: str
    severity: str
    redacted_value: str
    partial_hash: str
    source_url: str


class FetchedFile(BaseModel):
    url: str
    content: str
    source_map_url: str | None = None
    source_map_found: bool = False
    # True for a synthetic entry recovered from a source map's own
    # sourcesContent — the original, unminified file, not something
    # fetched directly from the target.
    recovered_from_source_map: bool = False
    # Response headers (lowercased keys), when the fetcher captured them —
    # empty for a source-map-recovered entry (no real response of its own).
    headers: dict[str, str] = Field(default_factory=dict)


class FileAnalysis(BaseModel):
    url: str
    frameworks: list[str] = Field(default_factory=list)
    source_map_found: bool = False
    source_map_url: str | None = None
    # Session *name* only (e.g. "admin") — never the cookie value.
    discovered_via_session: str | None = None
    discovered_via_runtime: bool = False
    recovered_from_source_map: bool = False


class SubdomainFinding(BaseModel):
    domain: str
    source_url: str
    in_scope: bool
    note: str


class DanglingCnameFinding(BaseModel):
    """A discovered subdomain whose CNAME points at a service with a
    documented history of unclaimed-record takeover (GitHub Pages,
    Heroku, S3, ...). DNS resolution only -- this tool never makes an
    HTTP request to the CNAME target (it's outside the declared scope by
    definition), so this is a candidate for manual verification, never a
    confirmed takeover."""

    domain: str
    cname_target: str
    service_hint: str


class ParameterFinding(BaseModel):
    name: str
    source_url: str


class DomFinding(BaseModel):
    sink_pattern: str
    sink_value: str
    co_occurring_sources: list[str] = Field(default_factory=list)
    source_url: str


class CorsMisconfiguration(BaseModel):
    """`Access-Control-Allow-Origin: *` combined with
    `Access-Control-Allow-Credentials: true` — invalid per the Fetch spec
    (browsers reject the combination), so a server sending both anyway is
    an unambiguous misconfiguration signature, detectable from response
    headers alone with no probe Origin header needed."""

    source_url: str
    allow_origin: str
    allow_credentials: bool


class ThirdPartyScript(BaseModel):
    """A <script src> served from a domain other than the target's own —
    client-side supply-chain surface: a takeover or compromise of this
    third-party host puts attacker-controlled JS directly on the target's
    page. Pure discovery, not a claim that the host is vulnerable."""

    hostname: str
    script_url: str
    page_url: str


class PostMessageFinding(BaseModel):
    """A `message` event listener registered with no `.origin` check found
    anywhere else in the same file — a whole-file co-occurrence heuristic
    (like the DOM sink/source engine), not a proven data flow. A listener
    that trusts `event.data` regardless of sender is a classic DOM-XSS /
    account-takeover source."""

    source_url: str
    snippet_preview: str


class WebSocketFinding(BaseModel):
    """A `new WebSocket(...)` call with no visible token/auth hint nearby —
    a candidate for Cross-Site WebSocket Hijacking if the server relies on
    ambient cookie auth alone with no Origin check."""

    source_url: str
    snippet_preview: str


class GraphQLOperation(BaseModel):
    """A query/mutation/subscription operation name extracted from a JS
    bundle (e.g. a graphql-tag template literal reading
    'mutation UpdateRole { ... }') — a lightweight schema-reconstruction
    inventory, not a full type-system parse. A mutation is the
    highest-signal entry here: it reveals a state-changing server
    capability that may not appear anywhere in the visible UI."""

    operation_type: str
    operation_name: str
    source_url: str


class MassAssignmentFinding(BaseModel):
    """A privileged-looking field (role/isAdmin/permissions/ownerId/...)
    assigned inside an object literal near a state-changing (PATCH/PUT/
    POST) call — the shape of a client sending a field a server might
    blindly apply. A window heuristic, not a proven vulnerability: the
    server may already ignore or validate this field."""

    source_url: str
    field_name: str
    severity: str
    snippet_preview: str


class VulnerableLibraryFinding(BaseModel):
    """A known-vulnerable third-party library version, fingerprinted from
    its own preserved version banner (Retire.js-style; Terser/UglifyJS
    keep `/*! ... */` comments by default, which is why these survive
    minification). Presence of a vulnerable version is not proof the
    application is exploitable — it depends on which feature path is
    actually used."""

    source_url: str
    library_name: str
    detected_version: str
    vulnerable_below: str
    cve: str
    severity: str
    description: str


class GraphStats(BaseModel):
    node_count: int
    edge_count: int
    bundle_count: int


class SchemaDiscrepancy(BaseModel):
    url_only: list[str] = Field(default_factory=list)
    js_body_only: list[str] = Field(default_factory=list)
    both: list[str] = Field(default_factory=list)


class AIEndpointVerdict(BaseModel):
    evidence_id: str
    endpoint_value: str
    source_url: str
    bug_classes: list[str] = Field(default_factory=list)
    priority: str
    test_plan: str
    confidence: float
    prompt_version: str
    model: str


class ScanResult(BaseModel):
    scan_run_id: str
    started_at: datetime
    targets: list[str] = Field(default_factory=list)
    collected_urls: list[str] = Field(default_factory=list)
    denied_urls: list[str] = Field(default_factory=list)
    endpoints: list[Endpoint] = Field(default_factory=list)
    secrets: list[Secret] = Field(default_factory=list)
    files: list[FileAnalysis] = Field(default_factory=list)
    subdomains: list[SubdomainFinding] = Field(default_factory=list)
    parameters: list[ParameterFinding] = Field(default_factory=list)
    dom_findings: list[DomFinding] = Field(default_factory=list)
    cors_findings: list[CorsMisconfiguration] = Field(default_factory=list)
    third_party_scripts: list[ThirdPartyScript] = Field(default_factory=list)
    postmessage_findings: list[PostMessageFinding] = Field(default_factory=list)
    websocket_findings: list[WebSocketFinding] = Field(default_factory=list)
    mass_assignment_findings: list[MassAssignmentFinding] = Field(default_factory=list)
    vulnerable_libraries: list[VulnerableLibraryFinding] = Field(default_factory=list)
    graphql_operations: list[GraphQLOperation] = Field(default_factory=list)
    dangling_cnames: list[DanglingCnameFinding] = Field(default_factory=list)
    graph_stats: GraphStats | None = None
    endpoint_schema_discrepancy: SchemaDiscrepancy | None = None
    ai_verdicts: list[AIEndpointVerdict] = Field(default_factory=list)
    ai_injection_flags: list[str] = Field(default_factory=list)
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    auth_only_js_urls: list[str] = Field(default_factory=list)
    # Populated by the CLI from a prior snapshot, before generate_hypotheses()
    # runs, so the "historical evidence" scoring factor has something real
    # to check against — never faked when no history is available.
    historical_endpoint_values: list[str] = Field(default_factory=list)
    scan_diff: ScanDiff | None = None
    # URL *paths* (not full URLs) actually observed as real requests during
    # runtime browser capture — populated by the CLI before
    # generate_hypotheses() runs, exactly like historical_endpoint_values.
    runtime_confirmed_paths: list[str] = Field(default_factory=list)

    def normalized(self) -> ScanResult:
        """Deterministically ordered + deduplicated copy.

        Findings (urls/endpoints/secrets/...) must be identical across two
        back-to-back scans of the same fixtures/target — this is what the
        idempotency test checks. Only scan_run_id/started_at are allowed
        to differ between runs.
        """
        unique_endpoints = {(e.pattern_name, e.value, e.source_url): e for e in self.endpoints}
        unique_secrets = {(s.secret_type, s.partial_hash, s.source_url): s for s in self.secrets}
        unique_files = {f.url: f for f in self.files}
        unique_subdomains = {(s.domain, s.source_url): s for s in self.subdomains}
        unique_parameters = {(p.name, p.source_url): p for p in self.parameters}
        unique_dom_findings = {(d.sink_pattern, d.source_url): d for d in self.dom_findings}
        unique_cors_findings = {c.source_url: c for c in self.cors_findings}
        unique_third_party_scripts = {
            (t.hostname, t.script_url): t for t in self.third_party_scripts
        }
        unique_postmessage_findings = {p.source_url: p for p in self.postmessage_findings}
        unique_websocket_findings = {
            (w.source_url, w.snippet_preview): w for w in self.websocket_findings
        }
        unique_mass_assignment_findings = {
            (m.source_url, m.field_name.lower()): m for m in self.mass_assignment_findings
        }
        unique_vulnerable_libraries = {
            (v.source_url, v.library_name, v.detected_version): v for v in self.vulnerable_libraries
        }
        unique_graphql_operations = {
            (g.operation_type, g.operation_name, g.source_url): g for g in self.graphql_operations
        }
        unique_dangling_cnames = {d.domain: d for d in self.dangling_cnames}
        unique_ai_verdicts = {v.evidence_id: v for v in self.ai_verdicts}
        unique_hypotheses = {h.id: h for h in self.hypotheses}

        return self.model_copy(
            update={
                "targets": sorted(set(self.targets)),
                "collected_urls": sorted(set(self.collected_urls)),
                "denied_urls": sorted(set(self.denied_urls)),
                "endpoints": sorted(
                    unique_endpoints.values(), key=lambda e: (e.pattern_name, e.value, e.source_url)
                ),
                "secrets": sorted(
                    unique_secrets.values(),
                    key=lambda s: (s.secret_type, s.partial_hash, s.source_url),
                ),
                "files": sorted(unique_files.values(), key=lambda f: f.url),
                "subdomains": sorted(
                    unique_subdomains.values(), key=lambda s: (s.domain, s.source_url)
                ),
                "parameters": sorted(
                    unique_parameters.values(), key=lambda p: (p.name, p.source_url)
                ),
                "dom_findings": sorted(
                    unique_dom_findings.values(), key=lambda d: (d.sink_pattern, d.source_url)
                ),
                "cors_findings": sorted(unique_cors_findings.values(), key=lambda c: c.source_url),
                "third_party_scripts": sorted(
                    unique_third_party_scripts.values(), key=lambda t: (t.hostname, t.script_url)
                ),
                "postmessage_findings": sorted(
                    unique_postmessage_findings.values(), key=lambda p: p.source_url
                ),
                "websocket_findings": sorted(
                    unique_websocket_findings.values(),
                    key=lambda w: (w.source_url, w.snippet_preview),
                ),
                "mass_assignment_findings": sorted(
                    unique_mass_assignment_findings.values(),
                    key=lambda m: (m.source_url, m.field_name.lower()),
                ),
                "vulnerable_libraries": sorted(
                    unique_vulnerable_libraries.values(),
                    key=lambda v: (v.source_url, v.library_name, v.detected_version),
                ),
                "graphql_operations": sorted(
                    unique_graphql_operations.values(),
                    key=lambda g: (g.operation_type, g.operation_name, g.source_url),
                ),
                "dangling_cnames": sorted(unique_dangling_cnames.values(), key=lambda d: d.domain),
                "ai_verdicts": sorted(unique_ai_verdicts.values(), key=lambda v: v.evidence_id),
                "ai_injection_flags": sorted(set(self.ai_injection_flags)),
                "hypotheses": sorted(unique_hypotheses.values(), key=lambda h: h.id),
                "auth_only_js_urls": sorted(set(self.auth_only_js_urls)),
                "historical_endpoint_values": sorted(set(self.historical_endpoint_values)),
                "runtime_confirmed_paths": sorted(set(self.runtime_confirmed_paths)),
            }
        )
