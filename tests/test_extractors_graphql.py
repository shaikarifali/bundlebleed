from __future__ import annotations

from bundlebleed.extractors.graphql import (
    detect_graphql_client,
    extract_graphql_operations,
    graphql_risk_flags,
)


def test_gql_template_mutation_detected() -> None:
    js = """
    import { gql } from '@apollo/client';
    const CREATE_USER = gql`
      mutation CreateUser($name: String!, $role: String!) {
        createUser(name: $name, role: $role) {
          id
          email
        }
      }
    `;
    """
    ops = extract_graphql_operations(js, "https://example.com/app.js")
    assert any(op.op_type == "mutation" and op.op_name == "CreateUser" for op in ops)


def test_variables_extracted() -> None:
    js = """
    const GET_USER = gql`
      query GetUser($userId: ID!, $tenantId: ID!) {
        user(id: $userId) { name email role }
      }
    `;
    """
    ops = extract_graphql_operations(js, "https://example.com/app.js")
    assert len(ops) >= 1
    op = ops[0]
    assert "userId" in op.variables
    assert "tenantId" in op.variables


def test_subscription_detected() -> None:
    js = """
    const MESSAGES_SUB = gql`
      subscription OnNewMessage($channelId: ID!) {
        newMessage(channelId: $channelId) { id text author }
      }
    `;
    """
    ops = extract_graphql_operations(js, "https://example.com/app.js")
    assert any(op.op_type == "subscription" for op in ops)


def test_persisted_query_detected() -> None:
    js = """
    client.query({
      extensions: {
        persistedQuery: {
          sha256Hash: "a" * 64
        }
      }
    });
    """
    # Use a real 64-char hex hash
    hash_val = "a" * 64
    js = f"""
    client.query({{
      extensions: {{
        persistedQuery: {{
          sha256Hash: "{hash_val}"
        }}
      }}
    }});
    """
    ops = extract_graphql_operations(js, "https://example.com/app.js")
    persisted = [op for op in ops if op.is_persisted]
    assert len(persisted) >= 1
    assert persisted[0].persisted_hash == hash_val


def test_endpoint_detected() -> None:
    js = """
    const client = new ApolloClient({
      uri: 'https://api.example.com/graphql',
    });
    """
    ops = extract_graphql_operations(js, "https://example.com/app.js")
    # Even with no operations, endpoint detection works via detect_graphql_client
    # The endpoint is embedded in each operation
    # Check a downstream operation picks up the endpoint
    js2 = js + """
    const Q = gql`query Me { me { id } }`;
    """
    ops2 = extract_graphql_operations(js2, "https://example.com/app.js")
    assert any("graphql" in op.endpoint for op in ops2)


def test_detect_graphql_client_true() -> None:
    js = "import { ApolloClient } from '@apollo/client';"
    assert detect_graphql_client(js)


def test_detect_graphql_client_false() -> None:
    js = "const x = fetch('/api/users');"
    assert not detect_graphql_client(js)


def test_risk_flags_sensitive_mutation() -> None:
    js = """
    const DELETE_USER = gql`
      mutation DeleteUser($userId: ID!) {
        deleteUser(id: $userId) { success }
      }
    `;
    """
    ops = extract_graphql_operations(js, "https://example.com/app.js")
    flags = graphql_risk_flags(ops)
    assert any("deleteuser" in f.lower() or "deleteUser" in f or "sensitive mutation" in f.lower() for f in flags)


def test_risk_flags_sensitive_variables() -> None:
    js = """
    const Q = gql`
      query GetAccount($tenantId: ID!) {
        account(tenantId: $tenantId) { name balance }
      }
    `;
    """
    ops = extract_graphql_operations(js, "https://example.com/app.js")
    flags = graphql_risk_flags(ops)
    assert any("tenantId" in f or "BOLA" in f for f in flags)


def test_deduplication() -> None:
    js = """
    const Q1 = gql`query GetUser($id: ID!) { user(id: $id) { name } }`;
    const Q2 = gql`query GetUser($id: ID!) { user(id: $id) { name } }`;
    """
    ops = extract_graphql_operations(js, "https://example.com/app.js")
    get_user_ops = [op for op in ops if op.op_name == "GetUser"]
    assert len(get_user_ops) == 1


def test_provenance_fields() -> None:
    js = "const Q = gql`query Foo { bar { id } }`;"
    ops = extract_graphql_operations(js, "https://example.com/app.js", file="/tmp/app.js")
    assert ops[0].file == "/tmp/app.js"
    assert ops[0].source_url == "https://example.com/app.js"
