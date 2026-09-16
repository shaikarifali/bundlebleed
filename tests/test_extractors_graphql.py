from __future__ import annotations

from bundlebleed.extractors.graphql import extract_graphql_operations


def test_extracts_named_mutation() -> None:
    content = (
        "const UPDATE_ROLE = gql`mutation UpdateRole($id: ID!, $role: String!) "
        "{ updateRole(id: $id, role: $role) { id role } }`;"
    )
    ops = extract_graphql_operations(content, source_url="https://e.com/app.js")
    assert len(ops) == 1
    assert ops[0].operation_type == "mutation"
    assert ops[0].operation_name == "UpdateRole"


def test_extracts_named_query() -> None:
    content = "const GET_USER = gql`query GetUser { user { id name email } }`;"
    ops = extract_graphql_operations(content, source_url="https://e.com/app.js")
    assert len(ops) == 1
    assert ops[0].operation_type == "query"
    assert ops[0].operation_name == "GetUser"


def test_extracts_named_subscription() -> None:
    content = "gql`subscription OnOrderUpdate { orderUpdated { id status } }`"
    ops = extract_graphql_operations(content, source_url="https://e.com/app.js")
    assert len(ops) == 1
    assert ops[0].operation_type == "subscription"


def test_extracts_multiple_distinct_operations() -> None:
    content = (
        "gql`query GetUser { user { id } }`;"
        "gql`mutation DeleteUser($id: ID!) { deleteUser(id: $id) }`;"
        "gql`mutation UpdateProfile($input: ProfileInput!) "
        "{ updateProfile(input: $input) { id } }`;"
    )
    ops = extract_graphql_operations(content, source_url="https://e.com/app.js")
    assert {(o.operation_type, o.operation_name) for o in ops} == {
        ("query", "GetUser"),
        ("mutation", "DeleteUser"),
        ("mutation", "UpdateProfile"),
    }


def test_repeated_operation_in_same_file_is_reported_once() -> None:
    content = "gql`mutation UpdateRole { updateRole { id } }`;" * 5
    ops = extract_graphql_operations(content, source_url="https://e.com/app.js")
    assert len(ops) == 1


def test_no_graphql_operation_produces_no_findings() -> None:
    ops = extract_graphql_operations("const x = 1;", source_url="https://e.com/app.js")
    assert ops == []
