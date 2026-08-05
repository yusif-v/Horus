"""Base types and interfaces for AI-powered weekly report analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable


@dataclass
class NarrativeSections:
    """Four narrative sections that the AI generates."""

    executive_summary: str = ""
    trend_analysis: str = ""
    risk_assessment: str = ""
    recommended_actions: str = ""

    def render(self) -> str:
        """Combine sections into a single prose block."""
        parts = []
        if self.executive_summary:
            parts.append(self.executive_summary)
        if self.trend_analysis:
            parts.append(self.trend_analysis)
        if self.risk_assessment:
            parts.append(self.risk_assessment)
        if self.recommended_actions:
            parts.append(self.recommended_actions)
        return "\n\n".join(parts)


@dataclass
class AIAnalysisResult:
    """Output of AI analysis — narrative + QA findings."""

    narrative: str = ""
    qa_issues: list[str] = field(default_factory=list)
    metadata: dict[str, str | int | float] = field(default_factory=dict)

    def is_valid(self) -> bool:
        """Check if result has usable narrative content."""
        return bool(self.narrative.strip())

    def has_qa_findings(self) -> bool:
        """Check if QA pass found any issues."""
        return len(self.qa_issues) > 0


class AIError(Exception):
    """Base exception for AI analysis failures."""


class AITimeoutError(AIError):
    """AI request timed out."""


class AIMalformedResponseError(AIError):
    """AI response could not be parsed."""


class AIUnavailableError(AIError):
    """AI provider not available (no API key, service down)."""


@runtime_checkable
class AbstractAIProvider(Protocol):
    """Provider-agnostic AI interface. Implementations: OpenAI, Anthropic, Ollama."""

    def analyze(self, prompt: str) -> AIAnalysisResult:
        """Send prompt to LLM and parse response into AIAnalysisResult."""
        ...
