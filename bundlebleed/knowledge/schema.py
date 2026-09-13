from __future__ import annotations

from bundlebleed.models import Endpoint, SchemaDiscrepancy


def endpoint_schema_discrepancy(
    url_endpoints: list[Endpoint], body_endpoints: list[Endpoint]
) -> SchemaDiscrepancy:
    """Compare endpoint values seen from cheap URL-string extraction against
    those seen only after downloading+beautifying the JS body (Phase 4.5's
    "schema discrepancy" idea, at the two sources this stage actually has).

    `js_body_only` is the interesting column: endpoints invisible unless you
    actually fetch the file.
    """
    url_values = {e.value for e in url_endpoints}
    body_values = {e.value for e in body_endpoints}
    return SchemaDiscrepancy(
        url_only=sorted(url_values - body_values),
        js_body_only=sorted(body_values - url_values),
        both=sorted(url_values & body_values),
    )
