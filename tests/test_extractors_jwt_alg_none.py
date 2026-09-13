from __future__ import annotations

import base64
import json

from bundlebleed.extractors.secrets import extract_secrets


def _jwt(header: dict[str, object], payload: dict[str, object], signature: str = "") -> str:
    def _b64(obj: dict[str, object]) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")

    return f"{_b64(header)}.{_b64(payload)}.{signature}"


def test_flags_unsigned_alg_none_jwt() -> None:
    token = _jwt({"alg": "none", "typ": "JWT"}, {"sub": "1", "admin": True})
    secrets = extract_secrets(f'var t = "{token}";', source_url="x")
    types = {s.secret_type for s in secrets}
    assert "jwt_token" in types
    assert "jwt_alg_none" in types
    alg_none = next(s for s in secrets if s.secret_type == "jwt_alg_none")
    assert alg_none.severity == "critical"


def test_case_insensitive_alg_none() -> None:
    token = _jwt({"alg": "None", "typ": "JWT"}, {"sub": "1"})
    secrets = extract_secrets(f'var t = "{token}";', source_url="x")
    assert "jwt_alg_none" in {s.secret_type for s in secrets}


def test_normal_signed_jwt_does_not_flag_alg_none() -> None:
    token = _jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "1"}, signature="realsignature123")
    secrets = extract_secrets(f'var t = "{token}";', source_url="x")
    types = {s.secret_type for s in secrets}
    assert "jwt_token" in types
    assert "jwt_alg_none" not in types


def test_never_returns_raw_jwt_value() -> None:
    token = _jwt({"alg": "none"}, {"sub": "1", "role": "admin"})
    secrets = extract_secrets(f'var t = "{token}";', source_url="x")
    for s in secrets:
        assert token not in s.redacted_value
        assert "*" in s.redacted_value


def test_duplicate_alg_none_jwt_is_deduped() -> None:
    token = _jwt({"alg": "none"}, {"sub": "1"})
    content = f'var a = "{token}"; var b = "{token}";'
    secrets = extract_secrets(content, source_url="x")
    alg_none_matches = [s for s in secrets if s.secret_type == "jwt_alg_none"]
    assert len(alg_none_matches) == 1
