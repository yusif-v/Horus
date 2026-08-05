"""Ollama (local LLM) provider for weekly report analysis."""

from __future__ import annotations

import logging

import requests

from .base import (
    AIAnalysisResult,
    AIMalformedResponseError,
    AITimeoutError,
    AIUnavailableError,
)
from .prompts import SYSTEM_PROMPT, parse_ai_response

logger = logging.getLogger(__name__)


class OllamaProvider:
    """Local LLM via Ollama. No API key required."""

    def __init__(
        self,
        model: str = "llama3:70b",
        url: str = "http://localhost:11434",
        timeout: int = 120,
    ) -> None:
        self.model = model
        self.url = url.rstrip("/")
        self.timeout = timeout

    def analyze(self, prompt: str) -> AIAnalysisResult:
        """Send prompt to Ollama and parse response."""
        try:
            response = requests.post(
                f"{self.url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": f"{SYSTEM_PROMPT}\n\n{prompt}",
                    "stream": False,
                    "options": {"temperature": 0.3},
                },
                timeout=self.timeout,
            )
            response.raise_for_status()
        except requests.exceptions.Timeout as e:
            raise AITimeoutError(f"Ollama request timed out after {self.timeout}s") from e
        except requests.exceptions.ConnectionError as e:
            raise AIUnavailableError(
                f"Cannot connect to Ollama at {self.url}. Is it running?"
            ) from e
        except requests.exceptions.RequestException as e:
            raise AIUnavailableError(f"Ollama request failed: {e}") from e

        try:
            body = response.json()
            raw_response = body.get("response", "")
        except (ValueError, KeyError) as e:
            raise AIMalformedResponseError(f"Invalid Ollama response: {e}") from e

        return parse_ai_response(raw_response)
