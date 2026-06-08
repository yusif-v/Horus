"""Minimal HTTP helper used by source modules."""

from __future__ import annotations
import json
import time
import urllib.error
import urllib.request

from ..config import HTTP_TIMEOUT, USER_AGENT


def fetch_json(
    url: str,
    accept: str | None = None,
    headers: dict[str, str] | None = None,
    max_retries: int = 3,
    base_delay: float = 2.0,
) -> dict:
    """Fetch URL and parse JSON. Retries with exponential backoff on transient errors."""
    final_headers = {'User-Agent': USER_AGENT}
    if accept:
        final_headers['Accept'] = accept
    if headers:
        final_headers.update(headers)

    last_error: Exception | None = None
    for attempt in range(max_retries):
        try:
            req = urllib.request.Request(url, headers=final_headers)
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            # Retry on 429 (rate limit), 500, 502, 503, 504
            if e.code in (429, 500, 502, 503, 504):
                last_error = e
                # Respect Retry-After header if present
                retry_after = e.headers.get('Retry-After')
                if retry_after:
                    try:
                        time.sleep(float(retry_after))
                        continue
                    except (ValueError, TypeError):
                        pass
                delay = base_delay * (2 ** attempt)
                time.sleep(delay)
                continue
            raise
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            last_error = e
            delay = base_delay * (2 ** attempt)
            time.sleep(delay)
            continue

    raise last_error or Exception(f"Failed after {max_retries} retries: {url}")
