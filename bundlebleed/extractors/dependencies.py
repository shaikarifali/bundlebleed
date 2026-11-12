from __future__ import annotations

import asyncio
import json
import re
import shutil

import structlog

from bundlebleed.models import VulnerableLibrary

logger = structlog.get_logger(__name__)

_BANNER_RE = re.compile(
    r"""(?:
        [/*!@]?\s*(?P<name>[A-Za-z][\w.\-]+)\s+v?(?P<version>\d+\.\d+[\.\d]*)
        |
        @version\s+(?P<ver2>\d+\.\d+[\.\d]*)
    )""",
    re.VERBOSE,
)

_KNOWN_LIBS = {
    "jquery": {"pattern": re.compile(r"jQuery\s+v?(\d+\.\d+[\.\d]*)"), "cve_versions": {"1.", "2.", "3.0", "3.1", "3.2", "3.3", "3.4", "3.5"}},
    "lodash": {"pattern": re.compile(r"lodash\s+v?(\d+\.\d+[\.\d]*)"), "cve_versions": {"4.0", "4.1", "4.2", "4.3", "4.4", "4.5", "4.6", "4.7"}},
    "angular": {"pattern": re.compile(r"AngularJS\s+v?(\d+\.\d+[\.\d]*)"), "cve_versions": {"1."}},
    "moment": {"pattern": re.compile(r"moment\.js\s+v?(\d+\.\d+[\.\d]*)"), "cve_versions": {""}},
    "bootstrap": {"pattern": re.compile(r"Bootstrap\s+v?(\d+\.\d+[\.\d]*)"), "cve_versions": {"2.", "3."}},
}


def _line_number(content: str, pos: int) -> int:
    return content.count("\n", 0, pos) + 1


async def _run_retire(beautified_dir: str) -> list[dict[str, object]]:
    """Run retire.js against the beautified directory and parse JSON output."""
    if not shutil.which("retire"):
        return []
    try:
        proc = await asyncio.create_subprocess_exec(
            "retire",
            "--jspath",
            beautified_dir,
            "--outputformat",
            "json",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate()
        raw = stdout.decode(errors="replace").strip()
        if not raw:
            return []
        data = json.loads(raw)
        if isinstance(data, dict) and "data" in data:
            return list(data["data"])
        if isinstance(data, list):
            return data
    except (json.JSONDecodeError, OSError):
        logger.warning("dependencies.retire_parse_failed")
    return []


def _regex_fallback(content: str, file: str) -> list[VulnerableLibrary]:
    """Scan banner comments for version strings when retire.js is not installed."""
    results: list[VulnerableLibrary] = []
    for name, info in _KNOWN_LIBS.items():
        m = info["pattern"].search(content)
        if not m:
            continue
        version = m.group(1)
        line_no = _line_number(content, m.start())
        is_old = any(version.startswith(prefix) for prefix in info["cve_versions"])
        results.append(
            VulnerableLibrary(
                name=name,
                version=version,
                latest="unknown",
                cves=["check-nvd"] if is_old else [],
                file=file,
                line=line_no,
            )
        )
    return results


async def _run_osv_scanner(lockfile_path: str) -> list[VulnerableLibrary]:
    """Run osv-scanner against a package lockfile and parse JSON output.

    Supports package-lock.json (npm), yarn.lock, pnpm-lock.yaml, requirements.txt.
    Degrades silently if osv-scanner is not installed.
    """
    if not shutil.which("osv-scanner"):
        return []
    try:
        proc = await asyncio.create_subprocess_exec(
            "osv-scanner",
            "--lockfile",
            lockfile_path,
            "--format",
            "json",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate()
        raw = stdout.decode(errors="replace").strip()
        if not raw:
            return []
        data = json.loads(raw)
        libs: list[VulnerableLibrary] = []
        # OSV-Scanner JSON: {"results": [{"packages": [{"package": {...}, "vulnerabilities": [...]}]}]}
        for result_block in data.get("results", []):
            for pkg in result_block.get("packages", []):
                pkg_info = pkg.get("package", {})
                pkg_name = str(pkg_info.get("name", ""))
                pkg_version = str(pkg_info.get("version", ""))
                vulns = pkg.get("vulnerabilities", [])
                if not vulns:
                    continue
                cve_ids = []
                for v in vulns:
                    for alias in v.get("aliases", []):
                        if alias.startswith("CVE-"):
                            cve_ids.append(alias)
                libs.append(
                    VulnerableLibrary(
                        name=pkg_name,
                        version=pkg_version,
                        latest="",
                        cves=cve_ids,
                        file=lockfile_path,
                        line=0,
                    )
                )
        logger.info("dependencies.osv_scanner_found", count=len(libs))
        return libs
    except (json.JSONDecodeError, OSError):
        logger.warning("dependencies.osv_scanner_parse_failed")
    return []


async def extract_dependencies(
    beautified_dir: str,
    file_contents: list[tuple[str, str]],
    lockfile_path: str | None = None,
) -> list[VulnerableLibrary]:
    """Detect vulnerable third-party libraries.

    Priority order:
    1. OSV-Scanner against a lockfile (highest fidelity — requires lockfile path)
    2. retire.js over the whole beautified directory
    3. Banner-comment regex scan (fallback, no external tools required)

    `file_contents` is a list of (file_path, content) for the fallback.
    Never contacts external services.
    """
    # Option 1: OSV-Scanner via lockfile
    if lockfile_path:
        osv_results = await _run_osv_scanner(lockfile_path)
        if osv_results:
            return osv_results

    # Option 2: retire.js
    retire_results = await _run_retire(beautified_dir)
    if retire_results:
        libs: list[VulnerableLibrary] = []
        for entry in retire_results:
            if not isinstance(entry, dict):
                continue
            file_path = str(entry.get("file", ""))
            for result in entry.get("results", []):
                if not isinstance(result, dict):
                    continue
                lib_name = str(result.get("component", ""))
                detected_ver = str(result.get("version", ""))
                for vuln in result.get("vulnerabilities", []):
                    if not isinstance(vuln, dict):
                        continue
                    cve_ids = [
                        str(id_)
                        for id_ in vuln.get("identifiers", {}).get("CVE", [])
                    ]
                    libs.append(
                        VulnerableLibrary(
                            name=lib_name,
                            version=detected_ver,
                            latest="",
                            cves=cve_ids,
                            file=file_path,
                            line=0,
                        )
                    )
        logger.info("dependencies.retire_found", count=len(libs))
        return libs

    # Option 3: banner-comment regex fallback
    logger.info("dependencies.using_regex_fallback")
    fallback: list[VulnerableLibrary] = []
    for file_path, content in file_contents:
        fallback.extend(_regex_fallback(content, file_path))
    return fallback
