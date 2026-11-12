from __future__ import annotations

from bundlebleed.ai.safety import flagged_unsafe_text


def test_flags_prohibited_keywords_case_insensitively() -> None:
    texts = ["Try a Brute Force attack.", "DROP TABLE users;"]
    assert flagged_unsafe_text(texts) == texts


def test_safe_text_is_not_flagged() -> None:
    texts = ["Compare responses across two low-privilege accounts."]
    assert flagged_unsafe_text(texts) == []


def test_only_unsafe_entries_are_returned() -> None:
    safe = "Inspect the response headers."
    unsafe = "Attempt a default password login."
    assert flagged_unsafe_text([safe, unsafe]) == [unsafe]
