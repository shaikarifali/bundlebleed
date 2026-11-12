from __future__ import annotations

from bundlebleed.models import Endpoint
from bundlebleed.processors.api_groups import group_endpoints


def _ep(value: str) -> Endpoint:
    return Endpoint(value=value, pattern_name="url_path", source_url="https://example.com/app.js")


def test_auth_group() -> None:
    eps = [_ep("/api/v1/login"), _ep("/api/v1/logout"), _ep("/api/v1/register")]
    groups = group_endpoints(eps)
    auth_group = next((g for g in groups if g.group_name == "auth"), None)
    assert auth_group is not None
    assert "/api/v1/login" in auth_group.endpoints


def test_admin_group() -> None:
    eps = [_ep("/api/admin/users"), _ep("/api/admin/settings")]
    groups = group_endpoints(eps)
    admin_group = next((g for g in groups if g.group_name == "admin"), None)
    assert admin_group is not None


def test_old_version_flagged() -> None:
    eps = [_ep("/api/v1/invoices"), _ep("/api/v2/invoices")]
    groups = group_endpoints(eps)
    for g in groups:
        if "/api/v1/invoices" in g.endpoints:
            assert "/api/v1/invoices" in g.old_versions
            break
    else:
        pytest.fail("endpoint not placed in any group")


def test_no_false_positive_old_version() -> None:
    eps = [_ep("/api/v1/invoices")]
    groups = group_endpoints(eps)
    for g in groups:
        assert "/api/v1/invoices" not in g.old_versions


def test_general_fallback() -> None:
    eps = [_ep("/api/random/stuff")]
    groups = group_endpoints(eps)
    names = [g.group_name for g in groups]
    assert "general" in names or "api" in names


def test_empty_input() -> None:
    assert group_endpoints([]) == []


def test_debug_group() -> None:
    eps = [_ep("/health"), _ep("/ping"), _ep("/metrics")]
    groups = group_endpoints(eps)
    debug_group = next((g for g in groups if g.group_name == "debug"), None)
    assert debug_group is not None
