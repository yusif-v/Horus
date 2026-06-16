"""Tests for horus/net/auth.py — GitHub token resolution."""

from __future__ import annotations

import os
from unittest.mock import patch

from horus.net.auth import github_token


def _clear_cache():
    github_token.cache_clear()


def test_github_token_env_var_set():
    _clear_cache()
    with patch.dict(os.environ, {"GITHUB_TOKEN": "ghp_test123"}, clear=False):
        # Remove GH_TOKEN if present
        os.environ.pop("GH_TOKEN", None)
        assert github_token() == "ghp_test123"


def test_github_token_falls_back_to_gh_token():
    _clear_cache()
    with patch.dict(os.environ, {"GH_TOKEN": "ghp_fallback"}, clear=False):
        os.environ.pop("GITHUB_TOKEN", None)
        assert github_token() == "ghp_fallback"


def test_github_token_strips_whitespace():
    _clear_cache()
    with patch.dict(os.environ, {"GITHUB_TOKEN": "  ghp_spaces  "}, clear=False):
        os.environ.pop("GH_TOKEN", None)
        assert github_token() == "ghp_spaces"


def test_github_token_returns_none_when_no_env_and_no_gh():
    _clear_cache()
    with patch.dict(os.environ, {}, clear=True):
        with patch("horus.net.auth.subprocess.run", side_effect=FileNotFoundError):
            assert github_token() is None


def test_github_token_caches_result():
    _clear_cache()
    with patch.dict(os.environ, {"GITHUB_TOKEN": "ghp_cached"}, clear=False):
        os.environ.pop("GH_TOKEN", None)
        # First call
        result1 = github_token()
        # Second call should use cache — change env to verify
        os.environ["GITHUB_TOKEN"] = "ghp_changed"
        result2 = github_token()
        assert result1 == result2 == "ghp_cached"
