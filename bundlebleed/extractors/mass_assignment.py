from __future__ import annotations

import re

from bundlebleed.models import MassAssignmentFinding

# Normalized field name -> severity. Authorization-critical (role/tenant/
# account boundary) fields are high; narrower-blast-radius business-logic
# fields are medium. Never low/info -- a mass-assignment candidate is
# either worth a hunter's time or it isn't in this detector's scope.
_FIELD_SEVERITY = {
    "role": "high",
    "isadmin": "high",
    "permissions": "high",
    "superuser": "high",
    "issuperuser": "high",
    "isstaff": "high",
    "organizationid": "high",
    "ownerid": "high",
    "accountid": "high",
    "verified": "medium",
    "isverified": "medium",
    "emailverified": "medium",
    "plan": "medium",
    "tier": "medium",
}

# WAI-ARIA role attribute values -- 'role: "button"' etc. is one of the most
# common strings in any modern JSX/HTML-generating bundle and has nothing to
# do with an authorization field also spelled "role". Excluding these is the
# difference between a usable detector and one that fires on every page.
_ARIA_ROLE_VALUES = {
    "alert", "alertdialog", "application", "article", "banner", "button", "cell",
    "checkbox", "columnheader", "combobox", "complementary", "contentinfo",
    "definition", "dialog", "directory", "document", "feed", "figure", "form",
    "grid", "gridcell", "group", "heading", "img", "link", "list", "listbox",
    "listitem", "log", "main", "marquee", "math", "menu", "menubar", "menuitem",
    "menuitemcheckbox", "menuitemradio", "navigation", "none", "note", "option",
    "presentation", "progressbar", "radio", "radiogroup", "region", "row",
    "rowgroup", "rowheader", "scrollbar", "search", "searchbox", "separator",
    "slider", "spinbutton", "status", "switch", "tab", "table", "tablist",
    "tabpanel", "term", "textbox", "timer", "toolbar", "tooltip", "tree",
    "treegrid", "treeitem",
}  # fmt: skip

_SENSITIVE_FIELD_RE = re.compile(
    r"(?i)\b(role|isAdmin|is_admin|permissions|ownerId|owner_id|organizationId|"
    r"organization_id|accountId|account_id|verified|isVerified|emailVerified|"
    r"email_verified|plan|tier|isStaff|is_staff|superuser|is_superuser)"
    r"\s*:\s*['\"]?([\w.\-]*)"
)
_STATE_CHANGING_METHOD_RE = re.compile(
    r"(?i)\.(?:patch|put|post)\s*\(|method\s*[:=]\s*['\"](?:PATCH|PUT|POST)['\"]"
)
_WINDOW = 200


def _normalize(field: str) -> str:
    return field.lower().replace("_", "")


def extract_mass_assignment_findings(content: str, source_url: str) -> list[MassAssignmentFinding]:
    """Flag a privileged-looking field assigned inside an object literal
    near a state-changing (PATCH/PUT/POST) call — the shape of a client
    sending a field a server might blindly apply. A local window, not
    whole-file, since the object literal and the method call are typically
    written close together.

    Deliberately high-signal only: 'role' is excluded when its value is a
    WAI-ARIA role keyword (button/dialog/tab/...), and only one finding per
    distinct field per file is reported, since a minified bundle can repeat
    the same field dozens of times.
    """
    findings: list[MassAssignmentFinding] = []
    seen_fields: set[str] = set()

    for match in _SENSITIVE_FIELD_RE.finditer(content):
        field = match.group(1)
        value = match.group(2)
        normalized = _normalize(field)

        if normalized in seen_fields:
            continue
        if normalized == "role" and value.lower() in _ARIA_ROLE_VALUES:
            continue

        start = max(0, match.start() - _WINDOW)
        end = min(len(content), match.end() + _WINDOW)
        window = content[start:end]
        if not _STATE_CHANGING_METHOD_RE.search(window):
            continue

        seen_fields.add(normalized)
        severity = _FIELD_SEVERITY[normalized]
        findings.append(
            MassAssignmentFinding(
                source_url=source_url,
                field_name=field,
                severity=severity,
                snippet_preview=window[:160],
            )
        )

    return findings
