from __future__ import annotations

from pathlib import Path

import yaml

from bundlebleed.scope.models import MatchType, ScanSettings, ScopeConfig, ScopeEntry


def _entry_from_token(token: str) -> ScopeEntry:
    if token.startswith("*."):
        return ScopeEntry(domain=token[2:], match_type=MatchType.WILDCARD)
    return ScopeEntry(domain=token, match_type=MatchType.EXACT)


def parse_scope_txt(text: str) -> ScopeConfig:
    """Parse the scope.txt format: one domain per line, '#' comments, '!' exclusions."""
    in_scope: list[ScopeEntry] = []
    out_of_scope: list[str] = []

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("!"):
            out_of_scope.append(line[1:].strip())
        else:
            in_scope.append(_entry_from_token(line))

    return ScopeConfig(in_scope=in_scope, out_of_scope=out_of_scope)


def parse_scope_txt_file(path: Path) -> ScopeConfig:
    return parse_scope_txt(path.read_text())


def parse_scope_yaml_file(path: Path) -> ScopeConfig:
    """Parse the full scope.yaml config format (project/scope/auth/scan/ai sections).

    `scope`, `authorization`, and `scan` are read and validated (a malformed
    one fails loudly). `auth` (login flow / session replay) and `ai` are
    reserved for later stages and are currently ignored rather than
    validated — they don't yet drive any behavior.
    """
    raw = yaml.safe_load(path.read_text()) or {}
    scope_section = raw.get("scope")
    if scope_section is None:
        raise ValueError(f"{path}: missing required 'scope' section")

    in_scope: list[ScopeEntry] = []
    for item in scope_section.get("in_scope", []):
        domain = item["domain"]
        match_type = MatchType.WILDCARD if item.get("type") == "wildcard" else MatchType.EXACT
        in_scope.append(ScopeEntry(domain=domain, match_type=match_type))

    out_of_scope = list(scope_section.get("out_of_scope", []))
    excluded_paths = list(scope_section.get("excluded_paths", []))

    authorization = raw.get("authorization", {}) or {}
    authorization_attested = bool(authorization.get("attested", False))

    scan_settings = ScanSettings.model_validate(raw.get("scan") or {})

    return ScopeConfig(
        in_scope=in_scope,
        out_of_scope=out_of_scope,
        excluded_paths=excluded_paths,
        authorization_attested=authorization_attested,
        scan=scan_settings,
    )


def parse_targets_arg(targets: str) -> ScopeConfig:
    """Parse a `-t "a.com,*.b.com"` style CLI argument into a ScopeConfig."""
    tokens = [t.strip() for t in targets.split(",") if t.strip()]
    return ScopeConfig(in_scope=[_entry_from_token(t) for t in tokens])


def load_scope_config(
    target: str | None, target_list: Path | None, config: Path | None
) -> ScopeConfig:
    """Resolve exactly one of -t / -tL / --config into a ScopeConfig.

    Fails loudly (per CLAUDE.md: never silently skip a malformed category)
    rather than picking one input when several — or none — are given.
    """
    sources = [("-t", target), ("-tL", target_list), ("--config", config)]
    provided = [name for name, value in sources if value]
    if len(provided) == 0:
        raise ValueError("one of -t, -tL, or --config is required")
    if len(provided) > 1:
        raise ValueError(f"only one of -t, -tL, --config may be given, got {', '.join(provided)}")

    if target is not None:
        return parse_targets_arg(target)
    if target_list is not None:
        return parse_scope_txt_file(target_list)
    assert config is not None
    return parse_scope_yaml_file(config)
