from __future__ import annotations

import re

from bundlebleed.models import GraphQLOperation

# Matches 'query GetUser(', 'mutation UpdateRole {', 'subscription OnEvent{'
# -- how graphql-tag/Apollo/Relay template literals and hand-written
# operation strings are written in practice. A lightweight inventory, not
# a full GraphQL parser: it captures the operation type/name, never
# attempts to reconstruct selection sets or the underlying schema.
_OPERATION_RE = re.compile(r"\b(query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]*)\s*[({]")


def extract_graphql_operations(content: str, source_url: str) -> list[GraphQLOperation]:
    """Extract named GraphQL query/mutation/subscription operations from JS
    content. One entry per distinct (type, name) pair per file -- a bundle
    that references the same operation many times (retries, hooks) isn't
    reported more than once."""
    seen: set[tuple[str, str]] = set()
    operations: list[GraphQLOperation] = []
    for match in _OPERATION_RE.finditer(content):
        operation_type, operation_name = match.group(1), match.group(2)
        key = (operation_type, operation_name)
        if key in seen:
            continue
        seen.add(key)
        operations.append(
            GraphQLOperation(
                operation_type=operation_type,
                operation_name=operation_name,
                source_url=source_url,
            )
        )
    return operations
