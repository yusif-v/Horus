"""GitHub token resolution.

Priority:
  1. GITHUB_TOKEN env var
  2. GH_TOKEN env var
  3. `gh auth token` (GitHub CLI keyring)
  4. None — unauthenticated, 60 req/hr limit
"""

from __future__ import annotations

import os
import subprocess
from functools import lru_cache


@lru_cache(maxsize=1)
def github_token() -> str | None:
    for var in ("GITHUB_TOKEN", "GH_TOKEN"):
        tok = os.environ.get(var)
        if tok:
            return tok.strip()

    try:
        proc = subprocess.run(
            ["gh", "auth", "token"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if proc.returncode == 0:
            tok = proc.stdout.strip()
            if tok:
                return tok
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    return None


@lru_cache(maxsize=1)
def codeberg_token() -> str | None:
    """Return Codeberg API token from CODEBERG_TOKEN env var, or None."""
    tok = os.environ.get("CODEBERG_TOKEN")
    if tok:
        return tok.strip()
    return None
