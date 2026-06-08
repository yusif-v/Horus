"""Minimal HTTP helper used by source modules."""


from __future__ import annotations
import json
import urllib.request

from ..config import HTTP_TIMEOUT, USER_AGENT


def fetch_json(
    url: str,
    accept: str | None = None,
    headers: dict[str, str] | None = None,
) -> dict:
    final_headers = {'User-Agent': USER_AGENT}
    if accept:
        final_headers['Accept'] = accept
    if headers:
        final_headers.update(headers)
    req = urllib.request.Request(url, headers=final_headers)
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
        return json.loads(resp.read())
