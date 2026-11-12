from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from bundlebleed.history.models import ScanDiff
from bundlebleed.hypotheses.models import Hypothesis


class Endpoint(BaseModel):
    value: str
    pattern_name: str
    source_url: str
    tag: Literal["live", "historical", "unauthed", "auth-required"] = "live"
    environment: Literal["prod", "staging", "dev", "unknown"] = "unknown"


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


class ParameterFinding(BaseModel):
    name: str
    source_url: str
    function_name: str | None = None


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


class EntropySecret(BaseModel):
    """High-entropy string with no known-regex match — potential credential."""

    file: str
    line: int
    entropy_score: float
    redacted_value: str
    partial_hash: str
    source_url: str


class InterestingComment(BaseModel):
    """Developer comment containing a security-relevant keyword."""

    text: str
    file: str
    line: int
    keyword_matched: str
    source_url: str


class FeatureFlag(BaseModel):
    """Detected feature flag — admin/internal keys feed the hypothesis engine."""

    key: str
    value_hint: str
    file: str
    line: int
    source_url: str


class VulnerableLibrary(BaseModel):
    """Third-party library with known CVEs (retire.js or regex fallback)."""

    name: str
    version: str
    latest: str
    cves: list[str] = Field(default_factory=list)
    file: str
    line: int


class Symbol(BaseModel):
    """Top-level JS symbol: global, export, or module binding."""

    name: str
    kind: Literal["global", "export", "module", "const", "let", "var", "function"]
    file: str
    line: int


class ApiGroup(BaseModel):
    """Endpoints clustered by functional area."""

    group_name: str
    endpoints: list[str] = Field(default_factory=list)
    old_versions: list[str] = Field(default_factory=list)


# Release 2 models — imported inline to avoid circular imports with extractors
# (extractors define their own Pydantic models; ScanResult references them here)
class GraphQLOperationRef(BaseModel):
    """Minimal reference to a GraphQL operation stored in ScanResult."""

    op_type: str
    op_name: str
    endpoint: str
    variables: list[str] = Field(default_factory=list)
    file: str
    line: int
    source_url: str
    is_persisted: bool = False


class WebSocketFindingRef(BaseModel):
    """Minimal reference to a WebSocket finding stored in ScanResult."""

    endpoint: str
    protocol: str
    auth_in_url: bool
    has_origin_check: bool
    file: str
    line: int
    source_url: str


class AuthFindingRef(BaseModel):
    """Minimal reference to an auth configuration finding stored in ScanResult."""

    finding_type: str
    detail: str
    severity_candidate: str
    file: str
    line: int
    source_url: str


class ObjectAccessCandidateRef(BaseModel):
    """Minimal reference to a BOLA/IDOR/mass-assignment candidate."""

    endpoint: str
    identifier: str
    function_name: str | None
    sensitive_properties: list[str] = Field(default_factory=list)
    level: int
    bug_class: str
    source_url: str


# Release 3 models — advanced client-side security reference types
class DomTaintFindingRef(BaseModel):
    """Minimal reference to a DOM taint finding stored in ScanResult."""

    source_name: str
    source_line: int
    sink_name: str
    sink_line: int
    sink_category: str
    file: str
    source_url: str


class ProtoPollutionFindingRef(BaseModel):
    """Minimal reference to a prototype pollution finding stored in ScanResult."""

    level: int
    pattern_name: str
    detail: str
    file: str
    line: int
    source_url: str


class PostMessageFindingRef(BaseModel):
    """Minimal reference to a postMessage finding stored in ScanResult."""

    kind: str
    target_origin: str | None
    has_origin_check: bool
    data_sinks: list[str] = Field(default_factory=list)
    file: str
    line: int
    source_url: str


class WorkerFindingRef(BaseModel):
    """Minimal reference to a service/web/shared worker finding."""

    worker_type: str
    worker_url: str | None
    has_fetch_intercept: bool
    is_inline_blob: bool
    file: str
    line: int
    source_url: str


class AssetGraphNodeRef(BaseModel):
    """Minimal reference to an asset graph node stored in ScanResult."""

    chunk_name: str | None
    chunk_url: str
    bundler: str
    dynamic_imports: list[str] = Field(default_factory=list)
    source_url: str


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
    # Phase 2 extended findings (Release 1)
    entropy_secrets: list[EntropySecret] = Field(default_factory=list)
    interesting_comments: list[InterestingComment] = Field(default_factory=list)
    feature_flags: list[FeatureFlag] = Field(default_factory=list)
    vulnerable_libraries: list[VulnerableLibrary] = Field(default_factory=list)
    symbols: list[Symbol] = Field(default_factory=list)
    api_groups: list[ApiGroup] = Field(default_factory=list)
    # Release 2 — API security intelligence
    graphql_operations: list[GraphQLOperationRef] = Field(default_factory=list)
    websocket_findings: list[WebSocketFindingRef] = Field(default_factory=list)
    auth_findings: list[AuthFindingRef] = Field(default_factory=list)
    object_access_candidates: list[ObjectAccessCandidateRef] = Field(default_factory=list)
    # Release 3 — Advanced client-side security
    dom_taint_findings: list[DomTaintFindingRef] = Field(default_factory=list)
    proto_pollution_findings: list[ProtoPollutionFindingRef] = Field(default_factory=list)
    postmessage_findings: list[PostMessageFindingRef] = Field(default_factory=list)
    worker_findings: list[WorkerFindingRef] = Field(default_factory=list)
    asset_graph_nodes: list[AssetGraphNodeRef] = Field(default_factory=list)

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
                "ai_verdicts": sorted(unique_ai_verdicts.values(), key=lambda v: v.evidence_id),
                "ai_injection_flags": sorted(set(self.ai_injection_flags)),
                "hypotheses": sorted(unique_hypotheses.values(), key=lambda h: h.id),
                "auth_only_js_urls": sorted(set(self.auth_only_js_urls)),
                "historical_endpoint_values": sorted(set(self.historical_endpoint_values)),
                "runtime_confirmed_paths": sorted(set(self.runtime_confirmed_paths)),
                "entropy_secrets": sorted(
                    {(e.partial_hash, e.source_url): e for e in self.entropy_secrets}.values(),
                    key=lambda e: (e.partial_hash, e.source_url),
                ),
                "interesting_comments": sorted(
                    {(c.file, c.line, c.keyword_matched): c for c in self.interesting_comments}.values(),
                    key=lambda c: (c.file, c.line),
                ),
                "feature_flags": sorted(
                    {(f.key, f.file, f.line): f for f in self.feature_flags}.values(),
                    key=lambda f: (f.key, f.file),
                ),
                "vulnerable_libraries": sorted(
                    {(v.name, v.version, v.file): v for v in self.vulnerable_libraries}.values(),
                    key=lambda v: (v.name, v.version),
                ),
                "symbols": sorted(
                    {(s.name, s.file, s.line): s for s in self.symbols}.values(),
                    key=lambda s: (s.name, s.file),
                ),
                "api_groups": sorted(
                    {g.group_name: g for g in self.api_groups}.values(),
                    key=lambda g: g.group_name,
                ),
                "graphql_operations": sorted(
                    {(op.op_type, op.op_name, op.source_url): op for op in self.graphql_operations}.values(),
                    key=lambda op: (op.op_type, op.op_name),
                ),
                "websocket_findings": sorted(
                    {(ws.endpoint, ws.source_url): ws for ws in self.websocket_findings}.values(),
                    key=lambda ws: ws.endpoint,
                ),
                "auth_findings": sorted(
                    {(af.finding_type, af.line, af.source_url): af for af in self.auth_findings}.values(),
                    key=lambda af: (af.finding_type, af.source_url),
                ),
                "object_access_candidates": sorted(
                    {(oc.endpoint, oc.bug_class, oc.source_url): oc for oc in self.object_access_candidates}.values(),
                    key=lambda oc: (-oc.level, oc.endpoint),
                ),
                "dom_taint_findings": sorted(
                    {(d.source_name, d.source_line, d.sink_name, d.sink_line, d.source_url): d for d in self.dom_taint_findings}.values(),
                    key=lambda d: (d.sink_category, d.source_url, d.sink_line),
                ),
                "proto_pollution_findings": sorted(
                    {(p.pattern_name, p.line, p.source_url): p for p in self.proto_pollution_findings}.values(),
                    key=lambda p: (-p.level, p.line),
                ),
                "postmessage_findings": sorted(
                    {(pm.kind, pm.line, pm.source_url): pm for pm in self.postmessage_findings}.values(),
                    key=lambda pm: (pm.kind, pm.source_url, pm.line),
                ),
                "worker_findings": sorted(
                    {(w.worker_type, w.worker_url or "__dynamic__", w.source_url): w for w in self.worker_findings}.values(),
                    key=lambda w: (w.worker_type, w.source_url),
                ),
                "asset_graph_nodes": sorted(
                    {n.chunk_url: n for n in self.asset_graph_nodes}.values(),
                    key=lambda n: n.chunk_url,
                ),
            }
        )
