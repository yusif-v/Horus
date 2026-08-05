"""Anthropic Claude provider for weekly report analysis."""

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
    from anthropic import Anthropic
except ImportError:
    Anthropic = None


class AnthropicProvider:
    """Anthropic Claude provider."""

    def __init__(
        self,
        api_key: str,
        model: str = "claude-sonnet-4-20250514",
        timeout: int = 120,
    ) -> None:
        self.api_key = api_key
        self.model = model
        self.timeout = timeout
        self._client: Anthropic | None = None

    def _get_client(self) -> Anthropic:
        if self._client is None:
            if Anthropic is None:
                raise AIUnavailableError(
                    "anthropic package not installed. Run: pip install horus[ai]"
                )
            try:
                self._client = Anthropic(api_key=self.api_key, timeout=self.timeout)
            except ImportError as e:
                raise AIUnavailableError(
                    "anthropic package not installed. Run: pip install horus[ai]"
                ) from e
        return self._client

    def analyze(self, prompt: str) -> AIAnalysisResult:
        """Send prompt to Claude and parse response."""
        client = self._get_client()
        try:
            response = client.messages.create(
                model=self.model,
                max_tokens=4096,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.3,
            )
            raw = response.content[0].text if response.content else ""
        except Exception as e:
            error_msg = str(e).lower()
            if "timeout" in error_msg:
                raise AITimeoutError(f"Anthropic request timed out: {e}") from e
            raise AIUnavailableError(f"Anthropic request failed: {e}") from e

        return parse_ai_response(raw)
