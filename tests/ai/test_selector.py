"""Tests for horus/ai/selector.py — provider selection."""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from horus.ai.base import AIUnavailableError
from horus.ai.selector import select_provider


class TestSelectProvider:
    def test_select_openai_from_env(self):
        with patch.dict(os.environ, {"HORUS_AI_PROVIDER": "openai", "OPENAI_API_KEY": "sk-test"}):
            provider = select_provider()
            assert provider.__class__.__name__ == "OpenAIProvider"

    def test_select_anthropic_from_env(self):
        with patch.dict(
            os.environ, {"HORUS_AI_PROVIDER": "anthropic", "ANTHROPIC_API_KEY": "sk-ant-test"}
        ):
            provider = select_provider()
            assert provider.__class__.__name__ == "AnthropicProvider"

    def test_select_ollama_from_env(self):
        with patch.dict(os.environ, {"HORUS_AI_PROVIDER": "ollama"}):
            provider = select_provider()
            assert provider.__class__.__name__ == "OllamaProvider"

    def test_select_with_explicit_override(self):
        with patch.dict(os.environ, {"HORUS_AI_PROVIDER": "openai", "OPENAI_API_KEY": "sk-test"}):
            provider = select_provider(provider="ollama")
            assert provider.__class__.__name__ == "OllamaProvider"

    def test_no_provider_env_raises(self):
        with patch.dict(os.environ, {}, clear=True):
            # Remove any AI-related env vars
            env = os.environ.copy()
            for key in list(env):
                if key.startswith("HORUS_AI") or key.endswith("_API_KEY"):
                    os.environ.pop(key, None)
            with pytest.raises(AIUnavailableError):
                select_provider()

    def test_openai_without_key_raises(self):
        with patch.dict(os.environ, {"HORUS_AI_PROVIDER": "openai"}, clear=True):
            if "OPENAI_API_KEY" in os.environ:
                del os.environ["OPENAI_API_KEY"]
            with pytest.raises(AIUnavailableError):
                select_provider()
