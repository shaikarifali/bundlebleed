from __future__ import annotations

from bundlebleed.extractors.mass_assignment import extract_mass_assignment_findings


def test_role_field_near_patch_call_is_flagged_high() -> None:
    content = "api.patch('/user', { ...profile, role: selectedRole });"
    findings = extract_mass_assignment_findings(content, source_url="https://e.com/app.js")
    assert len(findings) == 1
    assert findings[0].field_name == "role"
    assert findings[0].severity == "high"


def test_is_admin_field_near_post_call_is_flagged_high() -> None:
    content = "axios.post('/users', { name, isAdmin: true });"
    findings = extract_mass_assignment_findings(content, source_url="https://e.com/app.js")
    assert len(findings) == 1
    assert findings[0].severity == "high"


def test_verified_field_near_put_call_is_flagged_medium() -> None:
    content = "fetch('/profile', { method: 'PUT', body: JSON.stringify({ verified: true }) });"
    findings = extract_mass_assignment_findings(content, source_url="https://e.com/app.js")
    assert len(findings) == 1
    assert findings[0].field_name == "verified"
    assert findings[0].severity == "medium"


def test_role_field_far_from_any_state_changing_call_is_not_flagged() -> None:
    content = "const role = user.role; " + ("x" * 300) + " console.log(role);"
    findings = extract_mass_assignment_findings(content, source_url="https://e.com/app.js")
    assert findings == []


def test_aria_role_attribute_value_is_not_flagged() -> None:
    # 'role: "button"' is a WAI-ARIA attribute, not an authorization field --
    # this must never fire even sitting right next to a POST call.
    content = "axios.post('/analytics/click', { role: 'button', label: 'submit' });"
    findings = extract_mass_assignment_findings(content, source_url="https://e.com/app.js")
    assert findings == []


def test_role_with_non_aria_value_near_post_is_still_flagged() -> None:
    content = "axios.post('/analytics/click', { role: 'admin', label: 'submit' });"
    findings = extract_mass_assignment_findings(content, source_url="https://e.com/app.js")
    assert len(findings) == 1


def test_only_one_finding_per_distinct_field_per_file() -> None:
    content = "axios.patch('/a', { role: x });" + ("y" * 500) + "axios.patch('/b', { role: z });"
    findings = extract_mass_assignment_findings(content, source_url="https://e.com/app.js")
    assert len(findings) == 1


def test_no_sensitive_field_produces_no_finding() -> None:
    content = "axios.post('/comments', { text: comment });"
    findings = extract_mass_assignment_findings(content, source_url="https://e.com/app.js")
    assert findings == []
