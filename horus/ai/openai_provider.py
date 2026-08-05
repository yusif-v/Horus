"""OpenAI provider for weekly report analysis."""

from __future__ import annotations

import logging

from .base import (
    AIAnalysisResult,
    AITimeoutError,
    AIUnavailableError,
)
from .prompts import SYSTEM_PROMPT, parse_ai_response

logger = logging.getLogger(__name__)

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None  # type: ignore[assignment,misc]


class OpenAIProvider:
    """OpenAI GPT provider."""

    def __init__(
        self,
        api_key: str,
        model: str = "gpt-4o",
        timeout: int = 120,
    ) -> None:
        self.api_key = api_key
        self.model = model
        self.timeout = timeout
        self._client = None

    def _get_client(self):
        if self._client is None:
            if OpenAI is None:
                raise AIUnavailableError("openai package not installed. Run: pip install horus[ai]")
            self._client = OpenAI(api_key=self.api_key, timeout=self.timeout)
        return self._client

    def analyze(self, prompt: str) -> AIAnalysisResult:
        """Send prompt to OpenAI and parse response."""
        client = self._get_client()
        try:
            response = client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.3,
                response_format={"type": "text"},
            )
            raw = response.choices[0].message.content
        except Exception as e:
            error_msg = str(e).lower()
            if "timeout" in error_msg:
                raise AITimeoutError(f"OpenAI request timed out: {e}") from e
            raise AIUnavailableError(f"OpenAI request failed: {e}") from e

        return parse_ai_response(raw or "")
