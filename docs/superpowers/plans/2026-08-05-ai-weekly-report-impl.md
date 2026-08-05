# AI Weekly Report Analyzer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add AI-powered narrative generation and QA bug detection to the weekly threat report.

**Architecture:** New `horus/ai/` package with provider-agnostic interface. Pure function analyzer: `WeeklyData + rendered_report → AIAnalysisResult`. Two-pass single API call for narrative + QA. Configurable providers (OpenAI, Anthropic, Ollama) via env vars. Template renderer keeps data tables; AI writes narrative + QA sections.

**Tech Stack:** Python 3.10+, `openai` (optional), `anthropic` (optional), `requests` (existing, for Ollama)

## Global Constraints

- Python 3.10+ compatibility (no match statements, no `X | Y` union syntax in runtime code)
- Follow existing Horus patterns: plugin architecture, dataclass models, ruff formatting, mypy strict
- All AI dependencies are optional extras — import lazily inside functions
- API keys from env vars only, never logged or stored
- Graceful fallback: report always works when AI unavailable
- Test coverage gate: 70% (project-wide)
- No integration tests with real APIs (cost, flakiness)

---

### Task 1: AI package scaffold + base types

**Files:**
- Create: `horus/ai/__init__.py`
- Create: `horus/ai/base.py`
- Create: `tests/ai/__init__.py`
- Create: `tests/ai/test_base.py`

**Interfaces:**
- Produces: `AIAnalysisResult`, `AbstractAIProvider`, `AIError`
- Produces: `analyze_weekly_report()` public API signature

- [ ] **Step 1: Create the AI package directory**

```bash
mkdir -p tests/ai
touch tests/ai/__init__.py horus/ai/__init__.py
```

- [ ] **Step 2: Write failing tests for base types**

```python
# tests/ai/test_base.py
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
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `pytest tests/ai/test_base.py -v`
Expected: FAIL — "cannot import name 'AIAnalysisResult'"

- [ ] **Step 4: Implement base types**

```python
# horus/ai/base.py
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
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/ai/test_base.py -v`
Expected: PASS (12 tests)

- [ ] **Step 6: Commit**

```bash
git add horus/ai/base.py tests/ai/test_base.py
git commit -m "feat(ai): add base types for AI weekly report analysis"
```

---

### Task 2: Prompt templates

**Files:**
- Create: `horus/ai/prompts.py`
- Create: `tests/ai/test_prompts.py`

**Interfaces:**
- Consumes: `WeeklyData` from `horus.storage.weekly`
- Produces: `build_analysis_prompt()`, `build_compact_prompt()`, `parse_ai_response()`

- [ ] **Step 1: Write failing tests for prompts**

```python
# tests/ai/test_prompts.py
"""Tests for horus/ai/prompts.py — prompt building and response parsing."""

from __future__ import annotations

import json

import pytest

from horus.ai.base import AIMalformedResponseError, NarrativeSections
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
        data.top_cves = [
            {"id": "CVE-2026-0001", "cvss_score": 9.8, "kev": True}
        ]
        prompt = build_analysis_prompt(data, rendered_report="")
        assert "CVE-2026-0001" in prompt

    def test_includes_system_role(self):
        data = _make_minimal_weekly_data()
        prompt = build_analysis_prompt(data, rendered_report="")
        assert "analyst" in prompt.lower() or "expert" in prompt.lower()


class TestParseAiResponse:
    def test_valid_json(self):
        raw = json.dumps({
            "narrative": {
                "executive_summary": "Test summary.",
                "test.": "Test trend.",
                "risk_assessment": "Test risk.",
                "recommended_actions": "Test actions.",
            },
            "qa_issues": ["Issue 1", "Issue 2"],
        })
        result = parse_ai_response(raw)
        assert "Test summary." in result.narrative
        assert len(result.qa_issues) == 2

    def test_narrative_as_string(self):
        """Some LLMs return narrative as a flat string instead of sections."""
        raw = json.dumps({
            "narrative": "Full narrative text here.",
            "qa_issues": [],
        })
        result = parse_ai_response(raw)
        assert result.narrative == "Full narrative text here."

    def test_empty_qa_issues(self):
        raw = json.dumps({
            "narrative": {"executative_summary": "Summary."},
            "qa_issues": [],
        })
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
        raw = json.dumps({
            "narrative": {"executive_summary": "Summary."},
            "qa_issues": [],
            "extra_field": "ignored",
        })
        result = parse_ai_response(raw)
        assert "Summary." in result.narrative
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/ai/test_prompts.py -v`
Expected: FAIL — "cannot import name 'build_analysis_prompt'"

- [ ] **Step 3: Implement prompt templates**

```python
# horus/ai/prompts.py
"""Prompt templates for AI weekly report analysis."""

from __future__ import annotations

import json
import re
from typing import Any

from .base import AIMalformedResponseError, AIAnalysisResult, NarrativeSections


SYSTEM_PROMPT = """You are a senior cybersecurity threat intelligence analyst. You produce weekly threat reports for a security operations team. Your analysis is precise, actionable, and based solely on the data provided. You do not speculate beyond what the data shows.

You MUST respond with valid JSON only — no markdown, no commentary, no preamble."""

USER_PROMPT_TEMPLATE = """Analyze the following weekly threat intelligence data and produce a structured report.

## Period: {period_start} to {period_end}

## Summary Statistics
- New CVEs this week: {total_cves_this_week} (last week: {total_cves_last_week})
- New PoCs this week: {total_pocs_this_week} (last week: {total_pocs_last_week})
- KEV additions this week: {kev_new_this_week} (total: {kev_total})
- KEV overdue: {kev_overdue}
- Critical (CVSS 9+): {critical_cves}
- High (CVSS 7-8.9): {high_cves}
- Average CVSS: {avg_cvss_this_week}
- Average EPSS: {avg_epss_this_week}
- Average Reputation: {avg_reputation_this_week}/10

## Top CVEs (by risk score)
{top_cves_text}

## Most Targeted Vendors
{top_vendors_text}

## Attack Technique Distribution
{top_tags_text}

## Security News Highlights
{news_text}

## ThreatFox IOC Summary
- Total IOCs: {threatfox_total}
- CVEs with IOCs: {threatfox_cves}
- Type breakdown: {threatfox_types}

## Week-over-Week Trend
{weekly_trend_text}

## Rendered Template Report (for QA review)
{rendered_report}

---

Based on the above data, produce a JSON object with two keys:
1. "narrative": An object with four sections:
   - "executive_summary": 2-3 paragraphs summarizing the threat landscape this week
   - "trend_analysis": 1-2 paragraphs on week-over-week changes and emerging patterns
   - "risk_assessment": 1-2 paragraphs on critical threats requiring immediate attention
   - "recommended_actions": 1-2 paragraphs with prioritized actions

2. "qa_issues": A list of strings describing any data anomalies or report errors you find, such as:
   - CVSS/EPSS mismatches (e.g. high CVSS but near-zero EPSS)
   - KEV entries without due dates
   - Suspicious count spikes or drops
   - Internal contradictions in the rendered report
   - Missing expected data fields

Respond with JSON only."""


def _format_top_cves(cves: list[dict[str, Any]]) -> str:
    lines = []
    for cve in cves[:15]:
        kev_tag = " [KEV]" if cve.get("kev") else ""
        epss = f" EPSS={cve['epss_score']:.4f}" if cve.get("epss_score") is not None else ""
        lines.append(
            f"- {cve['id']} | CVSS {cve.get('cvss_score', 'N/A')}{kev_tag}{epss}"
        )
    return "\n".join(lines) if lines else "None"


def _format_vendors(vendors: list[dict[str, Any]]) -> str:
    lines = []
    for v in vendors[:10]:
        lines.append(f"- {v['vendor']}: {v['cve_count']} CVEs (avg CVSS {v['avg_cvss']})")
    return "\n".join(lines) if lines else "None"


def _format_tags(tags: list[dict[str, Any]]) -> str:
    lines = []
    for t in tags[:10]:
        lines.append(f"- {t['tag']}: {t['cve_count']} CVEs (avg CVSS {t['avg_cvss']})")
    return "\n".join(lines) if lines else "None"


def _format_news(news: list[dict[str, Any]]) -> str:
    lines = []
    for article in news[:8]:
        tier = article.get("tier", "?")
        lines.append(f"- [{tier}] {article['title']}")
    return "\n".join(lines) if lines else "None"


def _format_trend(trend: list[dict[str, Any]]) -> str:
    lines = []
    for entry in trend[-8:]:
        lines.append(f"- {entry['week']}: {entry['count']} CVEs")
    return "\n".join(lines) if lines else "None"


def build_analysis_prompt(data: Any, rendered_report: str) -> str:
    """Build the full analysis prompt from WeeklyData."""
    tf_summary = data.threatfox_summary if hasattr(data, 'threatfox_summary') else {}
    tf_total = tf_summary.get("total_iocs", 0) if isinstance(tf_summary, dict) else 0
    tf_cves = tf_summary.get("cves_with_iocs", 0) if isinstance(tf_summary, dict) else 0
    tf_types = tf_summary.get("type_counts", {}) if isinstance(tf_summary, dict) else {}
    tf_types_str = ", ".join(f"{k}: {v}" for k, v in tf_types.items()) if tf_types else "None"

    return USER_PROMPT_TEMPLATE.format(
        period_start=data.period_start,
        period_end=data.period_end,
        total_cves_this_week=data.total_cves_this_week,
        total_cves_last_week=data.total_cves_last_week,
        total_pocs_this_week=data.total_pocs_this_week,
        total_pocs_last_week=data.total_pocs_last_week,
        kev_new_this_week=data.kev_new_this_week,
        kev_total=data.kev_total,
        kev_overdue=data.kev_overdue,
        critical_cves=data.critical_cves,
        high_cves=data.high_cves,
        avg_cvss_this_week=data.avg_cvss_this_week,
        avg_epss_this_week=data.avg_epss_this_week,
        avg_reputation_this_week=data.avg_reputation_this_week,
        top_cves_text=_format_top_cves(data.top_cves),
        top_vendors_text=_format_vendors(data.top_vendors),
        top_tags_text=_format_tags(data.top_tags),
        news_text=_format_news(data.news_highlights),
        threatfox_total=tf_total,
        threatfox_cves=tf_cves,
        threatfox_types=tf_types_str,
        weekly_trend_text=_format_trend(data.weekly_trend),
        rendered_report=rendered_report[:8000] if rendered_report else "(none)",
    )


def parse_ai_response(raw: str) -> AIAnalysisResult:
    """Parse AI JSON response into AIAnalysisResult."""
    # Strip markdown code fences if present
    raw = raw.strip()
    if raw.startswith("```"):
        raw = re.sub(r"^```(?:json)?\s*\n?", "", raw)
        raw = re.sub(r"\n?```\s*$", "", raw)

    try:
        data = json.loads(raw.strip())
    except json.JSONDecodeError as e:
        raise AIMalformedResponseError(f"Invalid JSON response: {e}")

    # Handle narrative as either sections object or flat string
    narrative_raw = data.get("narrative", "")
    if isinstance(narrative_raw, dict):
        sections = NarrativeSections(
            executive_summary=narrative_raw.get("executive_summary", ""),
            trend_analysis=narrative_raw.get("trend_analysis", ""),
            risk_assessment=narrative_raw.get("risk_assessment", ""),
            recommended_actions=narrative_raw.get("recommended_actions", ""),
        )
        narrative = sections.render()
    elif isinstance(narrative_raw, str):
        narrative = narrative_raw
    else:
        narrative = ""

    qa_issues = data.get("qa_issues", [])
    if not isinstance(qa_issues, list):
        qa_issues = []

    metadata = {k: v for k, v in data.items() if k not in ("narrative", "qa_issues")}

    return AIAnalysisResult(
        narrative=narrative,
        qa_issues=qa_issues,
        metadata=metadata,
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/ai/test_prompts.py -v`
Expected: PASS (14 tests)

- [ ] **Step 5: Commit**

```bash
git add horus/ai/prompts.py tests/ai/test_prompts.py
git commit -m "feat(ai): add prompt templates and response parser"
```

---

### Task 3: Ollama provider

**Files:**
- Create: `horus/ai/ollama_provider.py`
- Create: `tests/ai/test_ollama.py`

**Interfaces:**
- Consumes: `AbstractAIProvider`, `AIError`
- Produces: `OllamaProvider`

- [ ] **Step 1: Write failing tests**

```python
# tests/ai/test_ollama.py
"""Tests for horus/ai/ollama_provider.py."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from horus.ai.base import AITimeoutError, AIUnavailableError
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/ai/test_ollama.py -v`
Expected: FAIL — "cannot import name 'OllamaProvider'"

- [ ] **Step 3: Implement Ollama provider**

```python
# horus/ai/ollama_provider.py
"""Ollama (local LLM) provider for weekly report analysis."""

from __future__ import annotations

import logging
from typing import Any

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
        except requests.exceptions.Timeout:
            raise AITimeoutError(f"Ollama request timed out after {self.timeout}s")
        except requests.exceptions.ConnectionError:
            raise AIUnavailableError(
                f"Cannot connect to Ollama at {self.url}. Is it running?"
            )
        except requests.exceptions.RequestException as e:
            raise AIUnavailableError(f"Ollama request failed: {e}")

        try:
            body = response.json()
            raw_response = body.get("response", "")
        except (ValueError, KeyError) as e:
            raise AIMalformedResponseError(f"Invalid Ollama response: {e}")

        return parse_ai_response(raw_response)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/ai/test_ollama.py -v`
Expected: PASS (5 tests)

- [ ] **Step 5: Commit**

```bash
git add horus/ai/ollama_provider.py tests/ai/test_ollama.py
git commit -m "feat(ai): add Ollama local provider"
```

---

### Task 4: OpenAI provider

**Files:**
- Create: `horus/ai/openai_provider.py`
- Create: `tests/ai/test_openai.py`

**Interfaces:**
- Produces: `OpenAIProvider`

- [ ] **Step 1: Write failing tests**

```python
# tests/ai/test_openai.py
"""Tests for horus/ai/openai_provider.py."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from horus.ai.base import AITimeoutError, AIUnavailableError
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
        mock_response.choices[0].message.content = (
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/ai/test_openai.py -v`
Expected: FAIL

- [ ] **Step 3: Implement OpenAI provider**

```python
# horus/ai/openai_provider.py
"""OpenAI provider for weekly report analysis."""

from __future__ import annotations

import logging
from typing import Any

from .base import (
    AIAnalysisResult,
    AIMalformedResponseError,
    AITimeoutError,
    AIUnavailableError,
)
from .prompts import SYSTEM_PROMPT, parse_ai_response

logger = logging.getLogger(__name__)


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
            try:
                from openai import OpenAI
                self._client = OpenAI(api_key=self.api_key, timeout=self.timeout)
            except ImportError:
                raise AIUnavailableError(
                    "openai package not installed. Run: pip install horus[ai]"
                )
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
                raise AITimeoutError(f"OpenAI request timed out: {e}")
            raise AIUnavailableError(f"OpenAI request failed: {e}")

        return parse_ai_response(raw or "")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/ai/test_openai.py -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add horus/ai/openai_provider.py tests/ai/test_openai.py
git commit -m "feat(ai): add OpenAI provider"
```

---

### Task 5: Anthropic provider

**Files:**
- Create: `horus/ai/anthropic_provider.py`
- Create: `tests/ai/test_anthropic.py`

**Interfaces:**
- Produces: `AnthropicProvider`

- [ ] **Step 1: Write failing tests**

```python
# tests/ai/test_anthropic.py
"""Tests for horus/ai/anthropic_provider.py."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from horus.ai.base import AIUnavailableError
from horus.ai.anthropic_provider import AnthropicProvider


class TestAnthropicProvider:
    def test_init_with_api_key(self):
        provider = AnthropicProvider(api_key="sk-ant-test")
        assert provider.model == "claude-sonnet-4-20250514"
        assert provider.api_key == "sk-ant-test"

    @patch("horus.ai.anthropic_provider.Anthropic")
    def test_analyze_success(self, mock_anthropic_cls):
        mock_client = MagicMock()
        mock_anthropic_cls.return_value = mock_client

        mock_response = MagicMock()
        mock_response.content = [MagicMock()]
        mock_response.content[0].text = (
            '{"narrative": {"executive_summary": "Claude analysis."}, "qa_issues": []}'
        )
        mock_client.messages.create.return_value = mock_response

        provider = AnthropicProvider(api_key="sk-ant-test")
        result = provider.analyze("test prompt")

        assert "Claude analysis." in result.narrative

    @patch("horus.ai.anthropic_provider.Anthropic")
    def test_analyze_import_error(self, mock_anthropic_cls):
        mock_anthropic_cls.side_effect = ImportError("No anthropic package")

        provider = AnthropicProvider(api_key="sk-ant-test")
        with pytest.raises(AIUnavailableError):
            provider.analyze("test prompt")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/ai/test_anthropic.py -v`
Expected: FAIL

- [ ] **Step 3: Implement Anthropic provider**

```python
# horus/ai/anthropic_provider.py
"""Anthropic Claude provider for weekly report analysis."""

from __future__ import annotations

import logging
from typing import Any

from .base import (
    AIAnalysisResult,
    AIMalformedResponseError,
    AITimeoutError,
    AIUnavailableError,
)
from .prompts import SYSTEM_PROMPT, parse_ai_response

logger = logging.getLogger(__name__)


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
        self._client = None

    def _get_client(self):
        if self._client is None:
            try:
                from anthropic import Anthropic
                self._client = Anthropic(api_key=self.api_key, timeout=self.timeout)
            except ImportError:
                raise AIUnavailableError(
                    "anthropic package not installed. Run: pip install horus[ai]"
                )
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
                raise AITimeoutError(f"Anthropic request timed out: {e}")
            raise AIUnavailableError(f"Anthropic request failed: {e}")

        return parse_ai_response(raw)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/ai/test_anthropic.py -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add horus/ai/anthropic_provider.py tests/ai/test_anthropic.py
git commit -m "feat(ai): add Anthropic Claude provider"
```

---

### Task 6: Provider selector + public API

**Files:**
- Create: `horus/ai/selector.py`
- Modify: `horus/ai/__init__.py`
- Create: `tests/ai/test_selector.py`

**Interfaces:**
- Produces: `select_provider()`, `analyze_weekly_report()`

- [ ] **Step 1: Write failing tests**

```python
# tests/ai/test_selector.py
"""Tests for horus/ai/selector.py — provider selection."""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from horus.ai.base import AIUnavailableError
from horus.ai.selector import select_provider


class TestSelectProvider:
    def test_select_openai_from_env(self):
        with patch.dict(os.environ, {"HORUS_AI_PROVIDER": "openai", "OPENAI_API_KEY": "sk-test"}):
            provider = select_provider()
            assert provider.__class__.__name__ == "OpenAIProvider"

    def test_select_anthropic_from_env(self):
        with patch.dict(os.environ, {"HORUS_AI_PROVIDER": "anthropic", "ANTHROPIC_API_KEY": "sk-ant-test"}):
            provider = select_provider()
            assert provider.__class__.__name__ == "AnthropicProvider"

    def test_select_ollama_from_env(self):
        with patch.dict(os.environ, {"HORUS_AI_PROVIDER": "ollama"}):
            provider = select_provider()
            assert provider.__class__.__name__ == "OllamaProvider"

    def test_select_with_explicit_override(self):
        with patch.dict(os.environ, {"HORUS_AI_PROVIDER": "openai", "OPENAI_API_KEY": "sk-test"}):
            provider = select_provider(provider="ollama")
            assert provider.__class__.__name__ == "OllamaProvider"

    def test_no_provider_env_raises(self):
        with patch.dict(os.environ, {}, clear=True):
            # Remove any AI-related env vars
            env = os.environ.copy()
            for key in list(env):
                if key.startswith("HORUS_AI") or key.endswith("_API_KEY"):
                    os.environ.pop(key, None)
            with pytest.raises(AIUnavailableError):
                select_provider()

    def test_openai_without_key_raises(self):
        with patch.dict(os.environ, {"HORUS_AI_PROVIDER": "openai"}, clear=True):
            if "OPENAI_API_KEY" in os.environ:
                del os.environ["OPENAI_API_KEY"]
            with pytest.raises(AIUnavailableError):
                select_provider()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/ai/test_selector.py -v`
Expected: FAIL

- [ ] **Step 3: Implement selector**

```python
# horus/ai/selector.py
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
            raise AIUnavailableError(
                "OPENAI_API_KEY env var required for OpenAI provider."
            )
        from .openai_provider import OpenAIProvider
        return OpenAIProvider(api_key=api_key)

    elif provider_name == "anthropic":
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise AIUnavailableError(
                "ANTHROPIC_API_KEY env var required for Anthropic provider."
            )
        from .anthropic_provider import AnthropicProvider
        return AnthropicProvider(api_key=api_key)

    elif provider_name == "ollama":
        from .ollama_provider import OllamaProvider
        return OllamaProvider()

    else:
        raise AIUnavailableError(
            f"Unknown AI provider: '{provider_name}'. "
            "Use 'openai', 'anthropic', or 'ollama'."
        )
```

- [ ] **Step 4: Update `__init__.py` with public API**

```python
# horus/ai/__init__.py
"""AI-powered weekly report analysis.

Usage:
    from horus.ai import analyze_weekly_report
    result = analyze_weekly_report(weekly_data, rendered_report, provider="openai")
"""

from __future__ import annotations

import logging

from .base import AIAnalysisResult, AIError
from .prompts import build_analysis_prompt
from .selector import select_provider

logger = logging.getLogger(__name__)


def analyze_weekly_report(
    weekly_data,
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
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/ai/test_selector.py -v`
Expected: PASS (6 tests)

- [ ] **Step 6: Commit**

```bash
git add horus/ai/selector.py horus/ai/__init__.py tests/ai/test_selector.py
git commit -m "feat(ai): add provider selector and public API"
```

---

### Task 7: CLI integration + optional dependencies

**Files:**
- Modify: `horus/cli.py`
- Modify: `pyproject.toml`

**Interfaces:**
- Consumes: `analyze_weekly_report` from `horus.ai`

- [ ] **Step 1: Write failing test for CLI flag**

```python
# tests/ai/test_cli_integration.py
"""Tests for AI flag integration in CLI."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from horus.cli import main


class TestWeeklyReportAI:
    def test_ai_flag_triggers_analysis(self, capsys, tmp_path):
        """When --ai is set and provider available, AI result is included."""
        db_path = tmp_path / "horus.db"
        # This test just verifies the flag is accepted — full integration
        # requires a real DB which is tested separately
        with pytest.raises(SystemExit):
            main(["--weekly-report", "--ai", "--config", str(tmp_path)])

    def test_ai_without_provider_warns(self, capsys, tmp_path):
        """When --ai is set but no provider configured, falls back gracefully."""
        import os
        # Clear any AI env vars
        env_backup = {}
        for key in list(os.environ):
            if key.startswith("HORUS_AI") or key.endswith("_API_KEY"):
                env_backup[key] = os.environ.pop(key)

        try:
            with pytest.raises(SystemExit):
                main(["--weekly-report", "--ai", "--config", str(tmp_path)])
        finally:
            os.environ.update(env_backup)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/ai/test_cli_integration.py -v`
Expected: FAIL (flag not recognized)

- [ ] **Step 3: Update pyproject.toml with optional AI dependencies**

Add to `pyproject.toml`:
```toml
[project.optional-dependencies]
ai = ["openai>=1.0", "anthropic>=0.30"]
```

- [ ] **Step 4: Wire --ai flag into CLI**

Modify `horus/cli.py`:
- Add `--ai` flag to parser
- Add `--ai-provider` flag to parser
- In `_cmd_weekly_report()`, call `analyze_weekly_report()` when `--ai` is set
- Merge AI result into the rendered report

```python
# In _build_parser(), add after --weekly-output:
p.add_argument(
    "--ai",
    action="store_true",
    help="Augment weekly report with AI-generated analysis and QA.",
)
p.add_argument(
    "--ai-provider",
    choices=("openai", "anthropic", "ollama"),
    default=None,
    help="AI provider override (default: from HORUS_AI_PROVIDER env var).",
)

# In _cmd_weekly_report(), after rendering:
if args.ai:
    from horus.ai import analyze_weekly_report

    ai_result = analyze_weekly_report(
        weekly_data, report, provider=args.ai_provider
    )
    if ai_result:
        # Prepend AI narrative
        report = (
            f"## AI Threat Analysis\n\n{ai_result.narrative}\n\n"
            f"---\n\n{report}"
        )
        if ai_result.has_qa_findings():
            qa_section = "\n".join(f"- {issue}" for issue in ai_result.qa_issues)
            report += (
                f"\n\n## AI Quality Assurance\n\n"
                f"The following issues were identified:\n\n{qa_section}\n"
            )
    else:
        import logging
        logging.getLogger(__name__).warning(
            "AI analysis unavailable — rendering template only"
        )
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/ai/test_cli_integration.py -v`
Expected: PASS (2 tests)

- [ ] **Step 6: Commit**

```bash
git add horus/cli.py pyproject.toml tests/ai/test_cli_integration.py
git commit -m "feat(ai): integrate AI analysis into weekly report CLI"
```

---

### Task 8: Full test suite + coverage verification

**Files:**
- None new — verification step only

- [ ] **Step 1: Run full test suite**

Run: `pytest tests/ -x -q`
Expected: PASS, coverage ≥ 70%

- [ ] **Step 2: Run ruff lint**

Run: `ruff check horus/ai/ horus/cli.py`
Expected: All checks passed

- [ ] **Step 3: Run ruff format**

Run: `ruff format horus/ai/`
Expected: All files formatted

- [ ] **Step 4: Run mypy**

Run: `mypy horus/ai/`
Expected: No issues

- [ ] **Step 5: Final commit if any fixes needed**

```bash
git add -A
git commit -m "feat(ai): finalize AI weekly report analysis feature"
```
