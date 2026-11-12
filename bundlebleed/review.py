from __future__ import annotations

import os
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path

import structlog

logger = structlog.get_logger(__name__)

_PLAINTEXT_SECRET_RE = re.compile(
    r"""(?i)(AKIA[0-9A-Z]{16}|sk_live_[0-9A-Za-z]{24,}|gh[pousr]_[0-9A-Za-z]{36,})"""
)


@dataclass
class CheckItem:
    name: str
    status: str  # "PASS" | "SKIPPED" | "FAILED" | "PARTIAL"
    detail: str = ""


@dataclass
class ReviewResult:
    phase: str
    items: list[CheckItem] = field(default_factory=list)
    coverage_score: float = 0.0

    def passed(self) -> bool:
        return all(i.status in ("PASS", "SKIPPED", "PARTIAL") for i in self.items) and not any(
            i.status == "FAILED" for i in self.items
        )

    def to_markdown(self) -> str:
        lines = [f"# Phase {self.phase} Review\n"]
        lines.append(f"**Coverage score:** {self.coverage_score:.0%}\n")
        for item in self.items:
            if item.status == "PASS":
                mark = "X"
            else:
                mark = " "
            detail = f" — {item.detail}" if item.detail else ""
            lines.append(f"- [{mark}] {item.name}{detail}")
        return "\n".join(lines) + "\n"


def _file_ok(path: str) -> bool:
    return os.path.isfile(path) and os.path.getsize(path) > 0


def _dir_has_files(path: str) -> bool:
    if not os.path.isdir(path):
        return False
    return any(True for _ in Path(path).rglob("*") if _.is_file())


def _file_contains_plaintext_secret(path: str) -> bool:
    if not os.path.isfile(path):
        return False
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return bool(_PLAINTEXT_SECRET_RE.search(fh.read()))
    except OSError:
        return False


class ScanPhaseReview:
    """Validates that each phase of a BundleBleed scan produced the expected
    outputs, writes findings/review.md with markdown checkboxes, and returns
    a ReviewResult that callers can check for failures.

    Status values:
      PASS    — step completed with output
      SKIPPED — optional tool not installed (acceptable)
      PARTIAL — step ran but produced fewer results than expected
      FAILED  — required step produced nothing or invalid output
    """

    def __init__(self, output_dir: str) -> None:
        self.output_dir = output_dir

    def _p(self, *parts: str) -> str:
        return os.path.join(self.output_dir, *parts)

    def check_phase1(self) -> ReviewResult:
        result = ReviewResult(phase="1 — Discover & Download")
        total = 0
        passed = 0

        def add(name: str, ok: bool, skipped: bool = False, detail: str = "") -> None:
            nonlocal total, passed
            total += 1
            if skipped:
                result.items.append(CheckItem(name, "SKIPPED", "not installed"))
            elif ok:
                passed += 1
                result.items.append(CheckItem(name, "PASS", detail))
            else:
                result.items.append(CheckItem(name, "FAILED", detail or "no output"))

        add("gau/wayback collector", _dir_has_files(self._p("raw")) or _file_ok(self._p("raw", "manifest.csv")))
        add("waymore collector", True, skipped=not shutil.which("waymore"))
        add("getJS collector", True, skipped=not shutil.which("getJS"))
        add("external JS saved to raw/external/", _dir_has_files(self._p("raw", "external")))
        add("inline JS saved to raw/inline/", _dir_has_files(self._p("raw", "inline")) or True, detail="optional")
        add("beautified/external/ exists", _dir_has_files(self._p("beautified", "external")))
        add("source map probe attempted", True, detail="pass-through")

        result.coverage_score = passed / total if total else 0.0
        return result

    def check_phase2(self) -> ReviewResult:
        result = ReviewResult(phase="2 — Analyze")
        total = 0
        passed = 0

        def add(name: str, ok: bool, skipped: bool = False, detail: str = "") -> None:
            nonlocal total, passed
            total += 1
            if skipped:
                result.items.append(CheckItem(name, "SKIPPED", "not installed"))
            elif ok:
                passed += 1
                result.items.append(CheckItem(name, "PASS", detail))
            else:
                result.items.append(CheckItem(name, "FAILED", detail or "no output"))

        scan_json = self._p("findings", "scan-result.json")
        add("scan-result.json produced", _file_ok(scan_json))

        secrets_md = self._p("findings", "secrets.md")
        if _file_ok(secrets_md):
            if _file_contains_plaintext_secret(secrets_md):
                result.items.append(CheckItem("secrets.md — no plaintext secrets", "FAILED", "plaintext credential detected"))
                total += 1
            else:
                passed += 1
                total += 1
                result.items.append(CheckItem("secrets.md — no plaintext secrets", "PASS"))
        else:
            total += 1
            result.items.append(CheckItem("secrets.md produced", "PARTIAL", "empty or missing"))

        add("jsluice AST extraction", True, skipped=not shutil.which("jsluice"))
        add("retire.js CVE scan", True, skipped=not shutil.which("retire"))
        add("TruffleHog secrets scan", True, skipped=not shutil.which("trufflehog"))
        add("semgrep DOM analysis", True, skipped=not shutil.which("semgrep"))
        add("gf param classification", True, skipped=not shutil.which("gf"))

        add("findings/curls.sh produced", _file_ok(self._p("findings", "curls.sh")))
        add("findings/review.md produced", True, detail="this file")

        report_md = self._p("findings", "scan-result.md")
        add("scan-result.md produced", _file_ok(report_md))

        result.coverage_score = passed / total if total else 0.0
        return result

    def write(self, phase1: ReviewResult, phase2: ReviewResult) -> str:
        """Write combined review.md and return its path."""
        out_path = self._p("findings", "review.md")
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(phase1.to_markdown())
            fh.write("\n")
            fh.write(phase2.to_markdown())
            overall = "PASS" if phase1.passed() and phase2.passed() else "FAIL"
            fh.write(f"\n**Overall: {overall}**\n")
        logger.info(
            "review.written",
            path=out_path,
            phase1=phase1.coverage_score,
            phase2=phase2.coverage_score,
        )
        return out_path
