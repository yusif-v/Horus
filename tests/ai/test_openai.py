"""Tests for horus/ai/openai_provider.py."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from horus.ai.base import AITimeoutError
from horus.ai.openai_provider import OpenAIProvider


class TestOpenAIProvider:
    def test_init_with_api_key(self):
        provider = OpenAIProvider(api_key="sk-test123")
        assert provider.model == "gpt-4o"
        assert provider.api_key == "sk-test123"

    def test_init_custom_model(self):
        provider = OpenAIProvider(api_key="sk-test", model="gpt-4o-mini")
        assert provider.model == "gpt-4o-mini"

    @patch("horus.ai.openai_provider.OpenAI")
    def test_analyze_success(self, mock_openai_cls):
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client

        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[
            0
        ].message.content = (
            '{"narrative": {"executive_summary": "AI summary."}, "qa_issues": ["bug1"]}'
        )
        mock_client.chat.completions.create.return_value = mock_response

        provider = OpenAIProvider(api_key="sk-test")
        result = provider.analyze("test prompt")

        assert "AI summary." in result.narrative
        assert "bug1" in result.qa_issues
        mock_client.chat.completions.create.assert_called_once()

    @patch("horus.ai.openai_provider.OpenAI")
    def test_analyze_timeout(self, mock_openai_cls):
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_client.chat.completions.create.side_effect = Exception("timeout")

        provider = OpenAIProvider(api_key="sk-test")
        with pytest.raises(AITimeoutError):
            provider.analyze("test prompt")
