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
    ("openai_api_key", "sk-" + "a" * 20 + "T3BlbkFJ" + "b" * 20),
    ("anthropic_api_key", "sk-ant-api03-" + "a" * 93 + "AA"),
    ("anthropic_admin_api_key", "sk-ant-admin01-" + "a" * 93 + "AA"),
    ("huggingface_token", "hf_" + "a" * 34),
    ("cohere_api_token", "cohere_token = " + "a" * 40),
    ("supabase_management_pat", "sbp_" + "a1b2c3d4" * 5),
    ("supabase_secret_key", "sb_secret_" + "a1b2c3d4" * 3),
    ("clerk_secret_key", "sk_live_" + "a" * 45),
    ("planetscale_token", "pscale_tkn_" + "a" * 32),
    ("posthog_personal_api_key", "phx_" + "a" * 45),
    ("cloudflare_global_api_key", "cloudflare_key: " + "f" * 37),
    ("cloudflare_api_token", "cloudflare_token = " + "a" * 40),
    ("digitalocean_pat", "dop_v1_" + "f" * 64),
    ("sentry_org_auth_token", "sntrys_eyJ" + "a" * 197),
    ("heroku_api_key_v2", "HRKU-AA" + "a" * 58),
    ("gitlab_pat", "glpat-" + "a" * 20),
    ("github_fine_grained_pat", "github_pat_" + "a" * 82),
    ("postman_api_key", "PMAK-" + "f" * 24 + "-" + "f" * 34),
    ("notion_api_token", "ntn_" + "1" * 11 + "a" * 35),
    ("algolia_admin_api_key", "algoliaAdminApiKey: " + "a" * 32),
    ("graphql_introspection_reference", "query IntrospectionQuery { __typename }"),
    ("cloud_storage_reference", "const bucket = 'mybucket.s3.amazonaws.com';"),
    ("cloud_metadata_reference", "fetch('http://169.254.169.254/latest/meta-data/')"),
    ("exposed_api_docs_path", "fetch('/swagger.json')"),
    ("exposed_vcs_config_path", "fetch('/.env')"),
    ("internal_hostname_reference", "const base = 'staging.api.acmecorp.com';"),
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


def test_posthog_project_key_is_not_flagged_as_personal_api_key() -> None:
    # 'phc_' is PostHog's intentionally-public project key, shipped by
    # design in every frontend snippet -- only 'phx_' (personal API key)
    # is a real secret.
    secrets = extract_secrets("posthog.init('phc_" + "a" * 45 + "')", source_url="x")
    types = {s.secret_type for s in secrets}
    assert "posthog_personal_api_key" not in types


def test_value_labeled_as_placeholder_nearby_is_not_flagged() -> None:
    secrets = extract_secrets(
        'const key = "AIza' + "a" * 35 + '"; // placeholder',
        source_url="x",
    )
    assert secrets == []


def test_value_labeled_as_example_nearby_is_not_flagged() -> None:
    secrets = extract_secrets(
        'const exampleKey = "AIza' + "a" * 35 + '"; // example only',
        source_url="x",
    )
    assert secrets == []


def test_stripe_test_key_is_still_flagged_despite_saying_test() -> None:
    # "test" is deliberately NOT a suppression keyword -- sk_test_ keys are
    # legitimately described as "test" in real code, and filtering that
    # word out would defeat the pattern's entire purpose.
    secrets = extract_secrets(
        "const stripeTestKey = 'sk_test_ABCDEFGHIJKLMNOPQRSTUVWX';", source_url="x"
    )
    types = {s.secret_type for s in secrets}
    assert "stripe_test_key" in types


def test_algolia_search_key_without_admin_keyword_is_not_flagged() -> None:
    # Algolia's public search-only key has the identical 32-char shape to
    # the admin key -- only flag when "admin" appears near the keyword.
    secrets = extract_secrets("algoliaSearchKey: " + "a" * 32, source_url="x")
    types = {s.secret_type for s in secrets}
    assert "algolia_admin_api_key" not in types
