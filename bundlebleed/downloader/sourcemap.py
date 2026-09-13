from __future__ import annotations

import json

from bundlebleed.models import FetchedFile


def parse_source_map(map_content: str, map_url: str) -> list[FetchedFile]:
    """Recover the original, unminified source files a source map embeds in
    its own `sourcesContent` array — often far richer than the shipped
    bundle (real variable names, comments, debug-only endpoints).

    Pure parsing, no network access — `map_content` is content the caller
    already fetched. Never raises: a malformed, unexpected-shape, or
    content-free map (many ship `sources` without embedded `sourcesContent`
    to save space) degrades to an empty list rather than aborting the scan.
    """
    try:
        data = json.loads(map_content)
    except (json.JSONDecodeError, ValueError):
        return []

    if not isinstance(data, dict):
        return []

    sources = data.get("sources")
    contents = data.get("sourcesContent")
    if not isinstance(sources, list) or not isinstance(contents, list):
        return []

    recovered: list[FetchedFile] = []
    for source_path, content in zip(sources, contents, strict=False):
        if not isinstance(source_path, str) or not isinstance(content, str) or not content:
            continue
        recovered.append(
            FetchedFile(
                url=f"{map_url} (source map: {source_path})",
                content=content,
                recovered_from_source_map=True,
            )
        )
    return recovered
