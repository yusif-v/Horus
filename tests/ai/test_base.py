"""Tests for horus/ai/base.py — base types and exceptions."""

from __future__ import annotations

import pytest

from horus.ai.base import (
    AbstractAIProvider,
    AIAnalysisResult,
    AIError,
    AIMalformedResponseError,
    AITimeoutError,
    AIUnavailableError,
    NarrativeSections,
)


class TestAIAnalysisResult:
    def test_creation_with_minimal_fields(self):
        result = AIAnalysisResult(
            narrative="Test narrative",
            qa_issues=[],
        )
        assert result.narrative == "Test narrative"
        assert result.qa_issues == []
        assert result.metadata == {}

    def test_creation_with_metadata(self):
        result = AIAnalysisResult(
            narrative="Test",
            qa_issues=["issue1"],
            metadata={"provider": "openai", "model": "gpt-4o"},
        )
        assert result.metadata["provider"] == "openai"

    def test_is_valid_with_narrative(self):
        result = AIAnalysisResult(narrative="Valid", qa_issues=[])
        assert result.is_valid() is True

    def test_is_valid_empty_narrative(self):
        result = AIAnalysisResult(narrative="", qa_issues=[])
        assert result.is_valid() is False

    def test_has_qa_findings(self):
        result = AIAnalysisResult(narrative="Test", qa_issues=["bug1"])
        assert result.has_qa_findings() is True

    def test_no_qa_findings(self):
        result = AIAnalysisResult(narrative="Test", qa_issues=[])
        assert result.has_qa_findings() is False


class TestNarrativeSections:
    def test_creation(self):
        sections = NarrativeSections(
            executive_summary="Summary",
            trend_analysis="Trends",
            risk_assessment="Risks",
            recommended_actions="Actions",
        )
        assert sections.executive_summary == "Summary"

    def test_render_combines_sections(self):
        sections = NarrativeSections(
            executive_summary="Exec summary text.",
            trend_analysis="Trend analysis text.",
            risk_assessment="Risk assessment text.",
            recommended_actions="Recommended actions text.",
        )
        rendered = sections.render()
        assert "Exec summary text." in rendered
        assert "Trend analysis text." in rendered
        assert "Risk assessment text." in rendered
        assert "Recommended actions text." in rendered


class TestExceptions:
    def test_ai_error_base(self):
        err = AIError("Something failed")
        assert str(err) == "Something failed"

    def test_ai_timeout_error(self):
        err = AITimeoutError("Timed out after 30s")
        assert "Timed out" in str(err)

    def test_ai_malformed_response(self):
        err = AIMalformedResponseError("Invalid JSON")
        assert "Invalid JSON" in str(err)

    def test_ai_unavailable_error(self):
        err = AIUnavailableError("No API key")
        assert "No API key" in str(err)


class TestAbstractAIProvider:
    def test_cannot_instantiate_abstract(self):
        with pytest.raises(TypeError):
            AbstractAIProvider()  # type: ignore
