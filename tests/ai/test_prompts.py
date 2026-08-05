"""Tests for horus/ai/prompts.py — prompt building and response parsing."""

from __future__ import annotations

import json

import pytest

from horus.ai.base import AIMalformedResponseError
from horus.ai.prompts import build_analysis_prompt, parse_ai_response
from horus.storage.weekly import WeeklyData


def _make_minimal_weekly_data() -> WeeklyData:
    return WeeklyData(
        period_start="2026-07-20",
        period_end="2026-07-27",
        previous_period_start="2026-07-13",
        previous_period_end="2026-07-20",
        generated_at="2026-08-05 18:00 UTC",
        total_cves_this_week=150,
        total_cves_last_week=120,
    )


class TestBuildAnalysisPrompt:
    def test_contains_period(self):
        data = _make_minimal_weekly_data()
        prompt = build_analysis_prompt(data, rendered_report="")
        assert "2026-07-20" in prompt
        assert "2026-07-27" in prompt

    def test_contains_cve_count(self):
        data = _make_minimal_weekly_data()
        prompt = build_analysis_prompt(data, rendered_report="")
        assert "150" in prompt

    def test_contains_rendered_report(self):
        data = _make_minimal_weekly_data()
        prompt = build_analysis_prompt(data, rendered_report="## Sample Report\nSome content")
        assert "Sample Report" in prompt

    def test_contains_json_format_instruction(self):
        data = _make_minimal_weekly_data()
        prompt = build_analysis_prompt(data, rendered_report="")
        assert "json" in prompt.lower()

    def test_contains_top_cves_when_present(self):
        data = _make_minimal_weekly_data()
        data.top_cves = [{"id": "CVE-2026-0001", "cvss_score": 9.8, "kev": True}]
        prompt = build_analysis_prompt(data, rendered_report="")
        assert "CVE-2026-0001" in prompt

    def test_includes_system_role(self):
        data = _make_minimal_weekly_data()
        prompt = build_analysis_prompt(data, rendered_report="")
        assert "analyst" in prompt.lower() or "expert" in prompt.lower()


class TestParseAiResponse:
    def test_valid_json(self):
        raw = json.dumps(
            {
                "narrative": {
                    "executive_summary": "Test summary.",
                    "trend_analysis": "Test trend.",
                    "risk_assessment": "Test risk.",
                    "recommended_actions": "Test actions.",
                },
                "qa_issues": ["Issue 1", "Issue 2"],
            }
        )
        result = parse_ai_response(raw)
        assert "Test summary." in result.narrative
        assert len(result.qa_issues) == 2

    def test_narrative_as_string(self):
        """Some LLMs return narrative as a flat string instead of sections."""
        raw = json.dumps(
            {
                "narrative": "Full narrative text here.",
                "qa_issues": [],
            }
        )
        result = parse_ai_response(raw)
        assert result.narrative == "Full narrative text here."

    def test_empty_qa_issues(self):
        raw = json.dumps(
            {
                "narrative": {"executive_summary": "Summary."},
                "qa_issues": [],
            }
        )
        result = parse_ai_response(raw)
        assert result.qa_issues == []

    def test_malformed_json_raises(self):
        raw = "This is not JSON at all"
        with pytest.raises(AIMalformedResponseError):
            parse_ai_response(raw)

    def test_partial_response_missing_narrative(self):
        raw = json.dumps({"qa_issues": ["Only issues, no narrative"]})
        result = parse_ai_response(raw)
        assert result.narrative == ""
        assert len(result.qa_issues) == 1

    def test_extra_fields_ignored(self):
        raw = json.dumps(
            {
                "narrative": {"executive_summary": "Summary."},
                "qa_issues": [],
                "extra_field": "ignored",
            }
        )
        result = parse_ai_response(raw)
        assert "Summary." in result.narrative

    def test_json_with_markdown_code_fence(self):
        """LLMs often wrap JSON in ```json ... ``` fences."""
        raw = '```json\n{"narrative": {"executive_summary": "Summary."}, "qa_issues": []}\n```'
        result = parse_ai_response(raw)
        assert "Summary." in result.narrative
        assert result.qa_issues == []

    def test_json_with_code_fence_no_language(self):
        """Code fence without 'json' language specifier."""
        raw = '```\n{"narrative": "Flat text.", "qa_issues": []}\n```'
        result = parse_ai_response(raw)
        assert result.narrative == "Flat text."

    def test_empty_input_raises(self):
        """Empty or whitespace-only input should raise AIMalformedResponseError."""
        with pytest.raises(AIMalformedResponseError):
            parse_ai_response("")

    def test_whitespace_only_input_raises(self):
        """Whitespace-only input should raise AIMalformedResponseError."""
        with pytest.raises(AIMalformedResponseError):
            parse_ai_response("   \n\t  ")

    def test_qa_issues_string_defensive_guard(self):
        """If LLM returns qa_issues as a string instead of list, default to empty list."""
        raw = json.dumps(
            {
                "narrative": {"executive_summary": "Summary."},
                "qa_issues": "This should be a list but is a string",
            }
        )
        result = parse_ai_response(raw)
        assert result.qa_issues == []

    def test_qa_issues_dict_defensive_guard(self):
        """If LLM returns qa_issues as a dict instead of list, default to empty list."""
        raw = json.dumps(
            {
                "narrative": {"executive_summary": "Summary."},
                "qa_issues": {"issue": "not a list"},
            }
        )
        result = parse_ai_response(raw)
        assert result.qa_issues == []
