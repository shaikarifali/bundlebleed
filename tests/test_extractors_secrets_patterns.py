from __future__ import annotations

import pytest

from bundlebleed.extractors.secrets import extract_secrets

# Each entry: (secret_type, content that SHOULD match, content that should NOT match)
# Values are synthetic/fake — recognizable formats, never a real credential.
SHOULD_MATCH_CASES = [
    (
        "aws_secret_key",
        'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"',
    ),
    ("stripe_test_key", "sk_test_ABCDEFGHIJKLMNOPQRSTUVWX"),
    (
        "slack_webhook_url",
        "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX",
    ),
    ("twilio_account_sid", "AC" + "a1b2c3d4" * 4),
    ("twilio_api_key_sid", "SK" + "a1b2c3d4" * 4),
    ("sendgrid_api_key", "SG." + "a" * 22 + "." + "b" * 43),
    ("mailgun_api_key", "key-" + "a1b2c3d4" * 4),
    ("npm_token", "npm_" + "a1B2c3D4" * 4 + "5678"),
    (
        "discord_webhook",
        "https://discord.com/api/webhooks/123456789012345678/AbCdEfGhIjKlMnOpQrSt",
    ),
    ("discord_bot_token", "M" + "a1B2c3D4e5F6g7H8i9J0k1L" + "." + "AbCdEf" + "." + "a" * 27),
    ("square_access_token", "sq0atp-" + "AbCdEfGhIjKlMnOpQrStUv"),
    ("square_oauth_secret", "sq0csp-" + "a" * 43),
    ("shopify_access_token", "shpat_" + "a1b2c3d4" * 4),
    ("mapbox_token", "pk." + "a" * 65 + "." + "b" * 25),
    (
        "paypal_braintree_access_token",
        "access_token$production$" + "a1b2c3d4e5f6g7h8" + "$" + "a" * 32,
    ),
    ("gcp_service_account_key", '"type": "service_account"'),
    ("azure_storage_account_key", "AccountKey=" + "a" * 86 + "=="),
    ("private_key_block", "-----BEGIN PRIVATE KEY-----"),
    ("private_key_block", "-----BEGIN OPENSSH PRIVATE KEY-----"),
    ("pgp_private_key_block", "-----BEGIN PGP PRIVATE KEY BLOCK-----"),
    ("generic_bearer_token", "Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456"),
    ("generic_api_key_assignment", 'const apiKey = "sk_abcdef0123456789";'),
]


@pytest.mark.parametrize("secret_type,content", SHOULD_MATCH_CASES)
def test_pattern_matches_expected_content(secret_type: str, content: str) -> None:
    secrets = extract_secrets(content, source_url="x")
    types = {s.secret_type for s in secrets}
    assert secret_type in types, f"expected {secret_type!r} to match {content!r}, got {types}"


def test_generic_api_key_assignment_does_not_match_unrelated_variable_names() -> None:
    # "AWS_KEY" contains "key" but not "api_key"/"apikey" as a whole token.
    secrets = extract_secrets('const AWS_KEY = "AKIAABCDEFGHIJKLMNOP";', source_url="x")
    types = {s.secret_type for s in secrets}
    assert "generic_api_key_assignment" not in types


def test_aws_secret_key_requires_context_keyword_not_just_length() -> None:
    # A bare 40-char base64-ish string with no "aws"/"secret"/"key" context
    # around it must not be flagged as an AWS secret key.
    secrets = extract_secrets(
        'var token = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";', source_url="x"
    )
    types = {s.secret_type for s in secrets}
    assert "aws_secret_key" not in types
