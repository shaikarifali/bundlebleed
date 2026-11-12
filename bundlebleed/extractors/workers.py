from __future__ import annotations

import re

from pydantic import BaseModel, Field


class WorkerFinding(BaseModel):
    """Service worker, web worker, or shared worker reference extracted from JS."""

    worker_type: str           # "service_worker" | "web_worker" | "shared_worker"
    worker_url: str | None     # script URL if extractable from literal
    has_fetch_intercept: bool  # service worker: intercepts all fetch events
    has_importscripts: bool    # worker uses importScripts()
    importscripts_urls: list[str] = Field(default_factory=list)
    is_inline_blob: bool       # created from blob URL — harder to inspect
    has_skip_waiting: bool     # SW uses skipWaiting() — aggressive cache takeover
    has_clients_claim: bool    # SW uses clients.claim()
    file: str
    line: int
    source_url: str


# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

# Service worker registration
_SW_REGISTER_RE = re.compile(
    r"""navigator\s*\.\s*serviceWorker\s*\.\s*register\s*\(\s*['"`]([^'"`]+)['"`]""",
    re.IGNORECASE,
)
_SW_REGISTER_VAR_RE = re.compile(
    r"""navigator\s*\.\s*serviceWorker\s*\.\s*register\s*\(""",
    re.IGNORECASE,
)

# Service worker event handlers (inside a SW script)
_SW_FETCH_RE = re.compile(r"""self\s*\.\s*addEventListener\s*\(\s*['"]fetch['"]""", re.IGNORECASE)
_SKIP_WAITING_RE = re.compile(r"""\bself\s*\.\s*skipWaiting\s*\(|\bskipWaiting\s*\(""", re.IGNORECASE)
_CLIENTS_CLAIM_RE = re.compile(r"""\bclients\s*\.\s*claim\s*\(""", re.IGNORECASE)

# importScripts() — may load untrusted external scripts in worker context
_IMPORT_SCRIPTS_RE = re.compile(r"""\bimportScripts\s*\(([^)]+)\)""", re.IGNORECASE)
_IMPORT_SCRIPTS_URL_RE = re.compile(r"""['"`]([^'"`]+)['"`]""")

# Web Worker creation
_WEB_WORKER_RE = re.compile(r"""\bnew\s+Worker\s*\(\s*['"`]([^'"`]+)['"`]""", re.IGNORECASE)
_WEB_WORKER_VAR_RE = re.compile(r"""\bnew\s+Worker\s*\(""", re.IGNORECASE)
_BLOB_WORKER_RE = re.compile(r"""\bnew\s+Worker\s*\(\s*URL\s*\.\s*createObjectURL""", re.IGNORECASE)

# Shared Worker
_SHARED_WORKER_RE = re.compile(r"""\bnew\s+SharedWorker\s*\(\s*['"`]([^'"`]+)['"`]""", re.IGNORECASE)
_SHARED_WORKER_VAR_RE = re.compile(r"""\bnew\s+SharedWorker\s*\(""", re.IGNORECASE)

# Worker message listener (inside a worker script)
_WORKER_MSG_RE = re.compile(
    r"""(?:self|onmessage)\s*\.\s*addEventListener\s*\(\s*['"]message['"]|\bonmessage\s*=""",
    re.IGNORECASE,
)


def _line_number(content: str, pos: int) -> int:
    return content.count("\n", 0, pos) + 1


def _extract_importscripts_urls(call_text: str) -> list[str]:
    return [m.group(1) for m in _IMPORT_SCRIPTS_URL_RE.finditer(call_text)]


def extract_worker_findings(
    content: str, source_url: str, file: str = ""
) -> list[WorkerFinding]:
    """Extract service worker, web worker, and shared worker references from JS.

    Service worker registrations in page-level JS and self.addEventListener in
    SW scripts are both detected.  Blob-URL workers are flagged separately since
    their source is not statically inspectable.

    Dedup: one finding per (worker_type, worker_url) pair; dynamic/blob workers
    at the same line are collapsed.
    """
    path = file or source_url
    findings: list[WorkerFinding] = []
    seen: set[tuple[str, str | None]] = set()

    # Gather file-wide signals that apply to all workers found
    has_fetch_intercept = bool(_SW_FETCH_RE.search(content))
    has_skip_waiting = bool(_SKIP_WAITING_RE.search(content))
    has_clients_claim = bool(_CLIENTS_CLAIM_RE.search(content))

    # importScripts calls
    imp_urls: list[str] = []
    for m in _IMPORT_SCRIPTS_RE.finditer(content):
        imp_urls.extend(_extract_importscripts_urls(m.group(1)))
    has_importscripts = bool(imp_urls)

    # --- Service workers ---
    for m in _SW_REGISTER_RE.finditer(content):
        worker_url = m.group(1)
        key = ("service_worker", worker_url)
        if key in seen:
            continue
        seen.add(key)
        findings.append(
            WorkerFinding(
                worker_type="service_worker",
                worker_url=worker_url,
                has_fetch_intercept=has_fetch_intercept,
                has_importscripts=has_importscripts,
                importscripts_urls=imp_urls,
                is_inline_blob=False,
                has_skip_waiting=has_skip_waiting,
                has_clients_claim=has_clients_claim,
                file=path,
                line=_line_number(content, m.start()),
                source_url=source_url,
            )
        )

    # Service worker registration with dynamic URL (no literal)
    for m in _SW_REGISTER_VAR_RE.finditer(content):
        if _SW_REGISTER_RE.match(content, m.start()):
            continue  # already captured by literal pattern
        key = ("service_worker", None)
        if key in seen:
            continue
        seen.add(key)
        findings.append(
            WorkerFinding(
                worker_type="service_worker",
                worker_url=None,
                has_fetch_intercept=has_fetch_intercept,
                has_importscripts=has_importscripts,
                importscripts_urls=imp_urls,
                is_inline_blob=False,
                has_skip_waiting=has_skip_waiting,
                has_clients_claim=has_clients_claim,
                file=path,
                line=_line_number(content, m.start()),
                source_url=source_url,
            )
        )
        break  # one per file for dynamic variant

    # --- Blob workers (before generic web worker, so we don't double-count) ---
    for m in _BLOB_WORKER_RE.finditer(content):
        key = ("web_worker", "__blob__")
        if key in seen:
            continue
        seen.add(key)
        findings.append(
            WorkerFinding(
                worker_type="web_worker",
                worker_url=None,
                has_fetch_intercept=False,
                has_importscripts=has_importscripts,
                importscripts_urls=imp_urls,
                is_inline_blob=True,
                has_skip_waiting=False,
                has_clients_claim=False,
                file=path,
                line=_line_number(content, m.start()),
                source_url=source_url,
            )
        )

    # --- Web workers ---
    for m in _WEB_WORKER_RE.finditer(content):
        worker_url = m.group(1)
        key = ("web_worker", worker_url)
        if key in seen:
            continue
        seen.add(key)
        findings.append(
            WorkerFinding(
                worker_type="web_worker",
                worker_url=worker_url,
                has_fetch_intercept=False,
                has_importscripts=has_importscripts,
                importscripts_urls=imp_urls,
                is_inline_blob=False,
                has_skip_waiting=False,
                has_clients_claim=False,
                file=path,
                line=_line_number(content, m.start()),
                source_url=source_url,
            )
        )

    # --- Shared workers ---
    for m in _SHARED_WORKER_RE.finditer(content):
        worker_url = m.group(1)
        key = ("shared_worker", worker_url)
        if key in seen:
            continue
        seen.add(key)
        findings.append(
            WorkerFinding(
                worker_type="shared_worker",
                worker_url=worker_url,
                has_fetch_intercept=False,
                has_importscripts=has_importscripts,
                importscripts_urls=imp_urls,
                is_inline_blob=False,
                has_skip_waiting=False,
                has_clients_claim=False,
                file=path,
                line=_line_number(content, m.start()),
                source_url=source_url,
            )
        )

    return findings


def worker_risk_flags(findings: list[WorkerFinding]) -> list[str]:
    """Human-readable risk summaries for worker findings."""
    flags: list[str] = []
    sw = [f for f in findings if f.worker_type == "service_worker"]
    if sw:
        intercept = [f for f in sw if f.has_fetch_intercept]
        if intercept:
            flags.append(
                f"Service worker intercepts all fetch events ({len(intercept)} registration(s)) — "
                "can proxy or modify any request/response"
            )
        skip_waiting = [f for f in sw if f.has_skip_waiting]
        if skip_waiting:
            flags.append(
                "Service worker uses skipWaiting() — new SW version activates immediately, "
                "potentially replacing cached assets for all tabs"
            )
    blob_workers = [f for f in findings if f.is_inline_blob]
    if blob_workers:
        flags.append(
            f"Blob-URL web worker(s) ({len(blob_workers)}) — script source is not statically inspectable, "
            "injection risk if blob content is derived from user input"
        )
    imp_script_workers = [f for f in findings if f.has_importscripts and f.importscripts_urls]
    if imp_script_workers:
        all_urls = {u for f in imp_script_workers for u in f.importscripts_urls}
        external = [u for u in all_urls if u.startswith("http")]
        if external:
            flags.append(
                f"Worker importScripts() loads {len(external)} external URL(s): {external[:3]} — "
                "third-party script execution inside worker context"
            )
    return flags
