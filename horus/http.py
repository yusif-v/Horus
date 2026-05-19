"""Minimal HTTP helper used by source modules."""

import json
import urllib.request

from .config import HTTP_TIMEOUT, USER_AGENT


def fetch_json(url: str, accept: str | None = None) -> dict:
    headers = {'User-Agent': USER_AGENT}
    if accept:
        headers['Accept'] = accept
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
        return json.loads(resp.read())
