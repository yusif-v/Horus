"""Tests for horus/ai/ollama_provider.py."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from horus.ai.base import AIAnalysisResult, AITimeoutError, AIUnavailableError
from horus.ai.ollama_provider import OllamaProvider


class TestOllamaProvider:
    def test_init_defaults(self):
        provider = OllamaProvider()
        assert provider.model == "llama3:70b"
        assert provider.url == "http://localhost:11434"

    def test_init_custom(self):
        provider = OllamaProvider(model="mistral", url="http://custom:1234")
        assert provider.model == "mistral"
        assert provider.url == "http://custom:1234"

    @patch("horus.ai.ollama_provider.requests.post")
    def test_analyze_success(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "response": '{"narrative": {"executive_summary": "Test."}, "qa_issues": []}'
        }
        mock_post.return_value = mock_response

        provider = OllamaProvider()
        result = provider.analyze("test prompt")
        assert isinstance(result, AIAnalysisResult)
        assert "Test." in result.narrative

    @patch("horus.ai.ollama_provider.requests.post")
    def test_analyze_timeout(self, mock_post):
        import requests

        mock_post.side_effect = requests.exceptions.Timeout()

        provider = OllamaProvider()
        with pytest.raises(AITimeoutError):
            provider.analyze("test prompt")

    @patch("horus.ai.ollama_provider.requests.post")
    def test_analyze_connection_error(self, mock_post):
        import requests

        mock_post.side_effect = requests.exceptions.ConnectionError()

        provider = OllamaProvider()
        with pytest.raises(AIUnavailableError):
            provider.analyze("test prompt")
