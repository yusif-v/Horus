"""AI-powered weekly report analysis.

Usage:
    from horus.ai import analyze_weekly_report
    result = analyze_weekly_report(weekly_data, rendered_report, provider="openai")
"""

from __future__ import annotations

import logging
from typing import Any

from .base import AIAnalysisResult, AIError
from .prompts import build_analysis_prompt
from .selector import select_provider

logger = logging.getLogger(__name__)


def analyze_weekly_report(
    weekly_data: Any,
    rendered_report: str,
    provider: str | None = None,
) -> AIAnalysisResult | None:
    """Analyze weekly report data with AI.

    Args:
        weekly_data: WeeklyData instance from gather_weekly_data().
        rendered_report: The rendered template report text.
        provider: Provider override ('openai', 'anthropic', 'ollama').
                 If None, uses HORUS_AI_PROVIDER env var.

    Returns:
        AIAnalysisResult with narrative and QA issues, or None if AI unavailable.
    """
    try:
        ai_provider = select_provider(provider)
    except AIError as e:
        logger.warning("AI provider unavailable: %s", e)
        return None

    prompt = build_analysis_prompt(weekly_data, rendered_report)

    try:
        result = ai_provider.analyze(prompt)
    except AIError as e:
        logger.warning("AI analysis failed: %s", e)
        return None

    return result
