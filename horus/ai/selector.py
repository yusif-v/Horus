"""Provider selection from environment/config."""

from __future__ import annotations

import logging
import os

from .base import AIUnavailableError

logger = logging.getLogger(__name__)


def select_provider(provider: str | None = None) -> object:
    """Select AI provider based on env vars or explicit override.

    Args:
        provider: Explicit provider name. If None, reads HORUS_AI_PROVIDER env var.

    Returns:
        An AbstractAIProvider instance.

    Raises:
        AIUnavailableError: If no provider is configured or API key is missing.
    """
    provider_name = provider or os.environ.get("HORUS_AI_PROVIDER", "").lower()

    if not provider_name:
        raise AIUnavailableError(
            "No AI provider configured. Set HORUS_AI_PROVIDER env var "
            "to 'openai', 'anthropic', or 'ollama'."
        )

    if provider_name == "openai":
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise AIUnavailableError("OPENAI_API_KEY env var required for OpenAI provider.")
        from .openai_provider import OpenAIProvider

        return OpenAIProvider(api_key=api_key)

    elif provider_name == "anthropic":
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise AIUnavailableError("ANTHROPIC_API_KEY env var required for Anthropic provider.")
        from .anthropic_provider import AnthropicProvider

        return AnthropicProvider(api_key=api_key)

    elif provider_name == "ollama":
        from .ollama_provider import OllamaProvider

        return OllamaProvider()

    else:
        raise AIUnavailableError(
            f"Unknown AI provider: '{provider_name}'. Use 'openai', 'anthropic', or 'ollama'."
        )
