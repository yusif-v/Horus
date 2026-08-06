"""Prompt templates for AI weekly report analysis."""

from __future__ import annotations

import json
import re
from typing import Any

from .base import AIAnalysisResult, AIMalformedResponseError, NarrativeSections

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
        lines.append(f"- {cve['id']} | CVSS {cve.get('cvss_score', 'N/A')}{kev_tag}{epss}")
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
    tf_summary = data.threatfox_summary if hasattr(data, "threatfox_summary") else {}
    tf_total = tf_summary.get("total_iocs", 0) if isinstance(tf_summary, dict) else 0
    tf_cves = tf_summary.get("cves_with_iocs", 0) if isinstance(tf_summary, dict) else 0
    tf_types = tf_summary.get("type_counts", {}) if isinstance(tf_summary, dict) else {}
    tf_types_str = ", ".join(f"{k}: {v}" for k, v in tf_types.items()) if tf_types else "None"

    user_prompt = USER_PROMPT_TEMPLATE.format(
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

    return SYSTEM_PROMPT + "\n\n" + user_prompt


def parse_ai_response(raw: str) -> AIAnalysisResult:
    """Parse AI JSON response into AIAnalysisResult."""
    raw = raw.strip()
    if raw.startswith("```"):
        raw = re.sub(r"^```(?:json)?\s*\n?", "", raw)
        raw = re.sub(r"\n?```\s*$", "", raw)

    try:
        data = json.loads(raw.strip())
    except json.JSONDecodeError as e:
        raise AIMalformedResponseError(f"Invalid JSON response: {e}") from e

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
