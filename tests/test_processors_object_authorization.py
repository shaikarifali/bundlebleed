from __future__ import annotations

from bundlebleed.models import Endpoint, ParameterFinding
from bundlebleed.processors.object_authorization import analyze_object_authorization


def _ep(value: str, source_url: str = "https://example.com/app.js") -> Endpoint:
    return Endpoint(value=value, pattern_name="url_path", source_url=source_url)


def _param(name: str, func: str | None = None, source_url: str = "https://example.com/app.js") -> ParameterFinding:
    return ParameterFinding(name=name, source_url=source_url, function_name=func)


def test_parameterized_endpoint_bola() -> None:
    eps = [_ep("/api/v1/invoices/:invoiceId")]
    candidates = analyze_object_authorization(eps, [], {})
    assert any(c.bug_class == "BOLA" for c in candidates)
    assert any(c.identifier == "invoiceId" for c in candidates)


def test_numeric_path_bola() -> None:
    eps = [_ep("/api/users/12345")]
    candidates = analyze_object_authorization(eps, [], {})
    assert any(c.bug_class == "BOLA" for c in candidates)


def test_id_query_param_bola() -> None:
    eps = [_ep("/api/documents?documentId=99999")]
    candidates = analyze_object_authorization(eps, [], {})
    assert any(c.bug_class == "BOLA" for c in candidates)


def test_cross_tenant_id_level4() -> None:
    eps = [_ep("/api/data?tenantId=550e8400e29b41d4")]
    candidates = analyze_object_authorization(eps, [], {})
    bola = [c for c in candidates if c.bug_class == "BOLA"]
    assert any(c.level == 4 for c in bola)


def test_function_name_raises_level() -> None:
    eps = [_ep("/api/accounts/:accountId")]
    params = [_param("accountId", func="getAccount")]
    candidates = analyze_object_authorization(eps, params, {})
    bola = [c for c in candidates if c.bug_class == "BOLA"]
    assert any(c.level >= 2 and c.function_name == "getAccount" for c in bola)


def test_bfla_admin_path() -> None:
    eps = [_ep("/api/admin/users")]
    candidates = analyze_object_authorization(eps, [], {})
    assert any(c.bug_class == "BFLA" for c in candidates)


def test_bfla_internal_path() -> None:
    eps = [_ep("/api/internal/settings")]
    candidates = analyze_object_authorization(eps, [], {})
    assert any(c.bug_class == "BFLA" for c in candidates)


def test_mass_assignment_detected() -> None:
    js_content = """
    const body = {
      ...formData,
      ...settings,
      isAdmin: false,
      role: 'user',
    };
    await fetch('/api/users/update', { method: 'PATCH', body: JSON.stringify(body) });
    """
    eps = [_ep("/api/users/update", source_url="https://example.com/app.js")]
    candidates = analyze_object_authorization(
        eps, [], {"https://example.com/app.js": js_content}
    )
    mass = [c for c in candidates if c.bug_class == "mass_assignment"]
    assert len(mass) >= 1
    assert any("isAdmin" in c.sensitive_properties or "role" in c.sensitive_properties for c in mass)


def test_no_findings_for_safe_endpoint() -> None:
    eps = [_ep("/api/products")]
    candidates = analyze_object_authorization(eps, [], {})
    assert candidates == []


def test_sorted_by_level_descending() -> None:
    eps = [
        _ep("/api/data?tenantId=x"),  # level 4
        _ep("/api/users/:userId"),     # level 1-2
    ]
    candidates = analyze_object_authorization(eps, [], {})
    if len(candidates) >= 2:
        assert candidates[0].level >= candidates[-1].level


def test_empty_input() -> None:
    assert analyze_object_authorization([], [], {}) == []
