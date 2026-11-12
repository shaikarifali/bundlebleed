from __future__ import annotations

from bundlebleed.extractors.secrets import extract_entropy_secrets


def test_high_entropy_string_detected() -> None:
    # 32 distinct chars → H = log2(32) = 5.0 bits, well above threshold
    js = 'const key = "rPmXkNqLvJhBfYwCzStUiOeAdGnTuVoW";'
    results = extract_entropy_secrets(js, "https://example.com/app.js")
    assert len(results) >= 1
    assert results[0].entropy_score >= 4.0


def test_low_entropy_string_not_detected() -> None:
    js = 'const val = "aaaaaaaaaaaaaaaaaaaaaa";'
    results = extract_entropy_secrets(js, "https://example.com/app.js")
    assert results == []


def test_short_string_not_detected() -> None:
    js = 'const x = "abc123";'
    results = extract_entropy_secrets(js, "https://example.com/app.js")
    assert results == []


def test_known_hash_skipped() -> None:
    import hashlib
    tok = "rPmXkNqLvJhBfYwCzStUiOeAdGnTuVoW"
    digest = hashlib.sha256(tok.encode()).hexdigest()[:12]
    js = f'const key = "{tok}";'
    results = extract_entropy_secrets(js, "https://example.com/app.js", known_hashes={digest})
    assert results == []


def test_plaintext_never_in_output() -> None:
    # Use a high-entropy string that won't match known-regex patterns
    # so it goes through entropy path
    js = 'const secret = "rPmXkNqLvJhBfYwCzStUiOeAdGnTuVoW";'
    results = extract_entropy_secrets(js, "https://example.com/app.js")
    for r in results:
        assert "rPmXkNqLvJhBfYwCzStUiOeAdGnTuVoW" not in r.redacted_value


def test_cap_at_500() -> None:
    # Generate content with 600 unique high-entropy tokens
    import hashlib
    tokens = [hashlib.sha256(f"seed{i}".encode()).hexdigest()[:32] for i in range(600)]
    js = "\n".join(f'const v{i} = "{t}";' for i, t in enumerate(tokens))
    results = extract_entropy_secrets(js, "https://example.com/app.js")
    assert len(results) <= 500


def test_provenance_fields() -> None:
    js = 'const key = "rPmXkNqLvJhBfYwCzStUiOeAdGnTuVoW";'
    results = extract_entropy_secrets(js, "https://example.com/app.js", file="/tmp/app.js")
    assert results[0].source_url == "https://example.com/app.js"
    assert results[0].file == "/tmp/app.js"
    assert results[0].line == 1
