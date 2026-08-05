"""Tests for horus/ai/anthropic_provider.py."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from horus.ai.anthropic_provider import AnthropicProvider
from horus.ai.base import AIUnavailableError


class TestAnthropicProvider:
    def test_init_with_api_key(self):
        provider = AnthropicProvider(api_key="sk-ant-test")
        assert provider.model == "claude-sonnet-4-20250514"
        assert provider.api_key == "sk-ant-test"

    @patch("horus.ai.anthropic_provider.Anthropic")
    def test_analyze_success(self, mock_anthropic_cls):
        mock_client = MagicMock()
        mock_anthropic_cls.return_value = mock_client

        mock_response = MagicMock()
        mock_response.content = [MagicMock()]
        mock_response.content[
            0
        ].text = '{"narrative": {"executive_summary": "Claude analysis."}, "qa_issues": []}'
        mock_client.messages.create.return_value = mock_response

        provider = AnthropicProvider(api_key="sk-ant-test")
        result = provider.analyze("test prompt")

        assert "Claude analysis." in result.narrative

    @patch("horus.ai.anthropic_provider.Anthropic")
    def test_analyze_import_error(self, mock_anthropic_cls):
        mock_anthropic_cls.side_effect = ImportError("No anthropic package")

        provider = AnthropicProvider(api_key="sk-ant-test")
        with pytest.raises(AIUnavailableError):
            provider.analyze("test prompt")
