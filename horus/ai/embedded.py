"""Embedded AI integration for weekly report analysis.

Uses local Ollama (no API key) to generate executive summaries
and actionable recommendations. Falls back to template-based
generation when Ollama is unavailable.

Usage:
    from horus.ai.embedded import generate_executive_summary, generate_recommendations
    summary = generate_executive_summary(data)
"""

from __future__ import annotations

import logging

from ..storage.weekly import WeeklyData

logger = logging.getLogger(__name__)

DEFAULT_MODEL = "llama3"
OLLAMA_URL = "http://localhost:11434"


def _is_ollama_available() -> bool:
    """Check if Ollama is running locally."""
    try:
        import requests

        resp = requests.get(f"{OLLAMA_URL}/api/tags", timeout=2)
        return resp.status_code == 200
    except Exception:
        return False


def _get_ollama_models() -> list[str]:
    """Get list of available Ollama models."""
    try:
        import requests

        resp = requests.get(f"{OLLAMA_URL}/api/tags", timeout=2)
        if resp.status_code == 200:
            data = resp.json()
            return [m.get("name", "") for m in data.get("models", [])]
    except Exception:
        pass
    return []


def _select_model(preferred: str = DEFAULT_MODEL) -> str:
    """Select best available model."""
    models = _get_ollama_models()
    if not models:
        return preferred
    # Check for exact match or variant
    for m in models:
        if preferred in m or m.startswith(preferred):
            return m
    return models[0]


def analyze_with_local_llm(prompt: str, model: str = DEFAULT_MODEL) -> str:
    """Send prompt to local Ollama instance.

    Args:
        prompt: The analysis prompt.
        model: Model name (default: llama3).

    Returns:
        Analysis text, or empty string if Ollama unavailable.
    """
    if not _is_ollama_available():
        logger.debug("Ollama not available for local LLM analysis")
        return ""

    actual_model = _select_model(model)
    try:
        import requests

        resp = requests.post(
            f"{OLLAMA_URL}/api/generate",
            json={
                "model": actual_model,
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0.4, "num_predict": 1024},
            },
            timeout=120,
        )
        resp.raise_for_status()
        return resp.json().get("response", "")
    except Exception as e:
        logger.warning("Local LLM analysis failed: %s", e)
        return ""


def generate_executive_summary(data: WeeklyData) -> str:
    """Generate executive summary using local LLM, fallback to template.

    Args:
        data: WeeklyData instance.

    Returns:
        Executive summary text (3-4 paragraphs).
    """
    prompt = _build_summary_prompt(data)
    llm_result = analyze_with_local_llm(prompt)
    if llm_result:
        return llm_result
    return _template_executive_summary(data)


def generate_recommendations(data: WeeklyData) -> str:
    """Generate actionable recommendations using local LLM, fallback to template.

    Args:
        data: WeeklyData instance.

    Returns:
        Recommendations text.
    """
    prompt = _build_recommendations_prompt(data)
    llm_result = analyze_with_local_llm(prompt)
    if llm_result:
        return llm_result
    return _template_recommendations(data)


def _build_summary_prompt(data: WeeklyData) -> str:
    """Build prompt for executive summary generation."""
    top_cve_str = ""
    if data.top_cves:
        top_cve_str = "\n".join(
            f"- {c['id']} (CVSS {c.get('cvss_score', 'N/A')}, EPSS {c.get('epss_score', 0):.3f})"
            for c in data.top_cves[:5]
        )

    kev_str = ""
    if data.kev_entries:
        overdue = sum(1 for k in data.kev_entries if k.get("is_overdue"))
        kev_str = f"Total KEVs: {len(data.kev_entries)}, Overdue: {overdue}"

    return f"""You are a cybersecurity threat intelligence analyst. Write a professional executive summary (3-4 paragraphs) for a weekly threat intelligence report.

Reporting period: {data.period_start} to {data.period_end}

KEY METRICS:
- New CVEs this week: {data.total_cves_this_week} (last week: {data.total_cves_last_week})
- Critical CVEs (CVSS 9+): {data.critical_cves}
- High CVEs (CVSS 7-8.9): {data.high_cves}
- Average CVSS: {data.avg_cvss_this_week}
- Average EPSS: {data.avg_epss_this_week:.3f}
- New PoCs: {data.total_pocs_this_week}
- New KEV additions: {data.kev_new_this_week}
{kev_str}

TOP CVES:
{top_cve_str}

IOC SUMMARY:
- Total extracted IOCs: {data.ioc_summary.get("total_iocs", 0)}
- Network IOCs: {data.ioc_summary.get("network_count", 0)}
- Host IOCs: {data.ioc_summary.get("host_count", 0)}

Write a concise, professional executive summary. Focus on key risks, trends, and actionable insights."""


def _build_recommendations_prompt(data: WeeklyData) -> str:
    """Build prompt for recommendations generation."""
    kev_items = []
    for k in data.kev_entries[:10]:
        due = k.get("kev_due_date", "unknown")
        overdue = "OVERDUE" if k.get("is_overdue") else ""
        kev_items.append(f"- {k['id']} (due: {due}) {overdue}")

    return f"""You are a cybersecurity threat intelligence analyst. Generate actionable recommendations based on this weekly threat data.

OVERDUE KEVS:
{chr(10).join(kev_items) if kev_items else "None"}

CRITICAL CVES: {data.critical_cves}
HIGH CVES: {data.high_cves}
AVG EPSS: {data.avg_epss_this_week:.3f}

IOC SUMMARY:
- Network IOCs (IPs, domains, URLs): {data.ioc_summary.get("network_count", 0)}
- Host IOCs (hashes, paths, registry): {data.ioc_summary.get("host_count", 0)}

Provide 5-8 specific, prioritized recommendations for security teams. Each should be actionable and reference specific data points."""


def _template_executive_summary(data: WeeklyData) -> str:
    """Template-based executive summary (fallback when no LLM)."""
    parts = []

    # Paragraph 1: Volume
    total = data.total_cves_this_week
    prev = data.total_cves_last_week
    if total > 0:
        direction = "increase" if total > prev else "decrease" if total < prev else "stable trend"
        p1 = (
            f"During the reporting period of {data.period_start} to {data.period_end}, "
            f"Horus tracked {total} new CVEs — a {direction} from the previous week ({prev}). "
            f"The average CVSS severity was {data.avg_cvss_this_week}, with "
            f"{data.critical_cves} critical and {data.high_cves} high-severity vulnerabilities "
            f"identified."
        )
    else:
        p1 = (
            f"No new CVEs were observed during {data.period_start} to {data.period_end}. "
            f"This may indicate reduced disclosure activity or collection gaps."
        )
    parts.append(p1)

    # Paragraph 2: KEV and exploits
    p2_parts = []
    if data.kev_new_this_week > 0:
        p2_parts.append(f"CISA added {data.kev_new_this_week} new entries to the KEV catalog")
    if data.kev_overdue > 0:
        p2_parts.append(f"{data.kev_overdue} KEV entries are past remediation deadline — URGENT")
    if data.total_pocs_this_week > 0:
        p2_parts.append(f"{data.total_pocs_this_week} new PoC exploits published")
    if p2_parts:
        parts.append(" ".join(p2_parts) + ".")

    # Paragraph 3: IOCs and intelligence
    ioc_total = data.ioc_summary.get("total_iocs", 0)
    if ioc_total > 0:
        parts.append(
            f"Threat intelligence analysis extracted {ioc_total} indicators of compromise "
            f"({data.ioc_summary.get('network_count', 0)} network, "
            f"{data.ioc_summary.get('host_count', 0)} host-based) from news, resources, "
            f"and ThreatFox feeds."
        )

    return "\n\n".join(parts)


def _template_recommendations(data: WeeklyData) -> str:
    """Template-based recommendations (fallback when no LLM)."""
    recs = []

    # KEV urgency
    if data.kev_overdue > 0:
        recs.append(
            f"**PRIORITY 1 — Patch Overdue KEVs:** {data.kev_overdue} CISA KEV entries are past "
            f"their remediation deadline. These require immediate patching or mitigation."
        )

    # Critical CVEs
    if data.critical_cves > 0:
        recs.append(
            f"**PRIORITY 1 — Address Critical CVEs:** {data.critical_cves} CVEs with CVSS 9+ were "
            f"identified. Prioritize those with high EPSS scores (>0.5) for immediate action."
        )

    # EPSS monitoring
    if data.avg_epss_this_week > 0.1:
        recs.append(
            f"**PRIORITY 2 — Monitor Rising EPSS:** Average EPSS this week is "
            f"{data.avg_epss_this_week:.3f}. Review CVEs with EPSS > 0.3 for exploit likelihood."
        )

    # IOCs
    if data.ioc_summary.get("network_count", 0) > 0:
        recs.append(
            "**PRIORITY 2 — Deploy Network IOCs:** Extract and block identified malicious "
            "IPs, domains, and URLs at perimeter defenses."
        )

    if data.ioc_summary.get("host_count", 0) > 0:
        recs.append(
            "**PRIORITY 2 — Deploy Host IOCs:** Add identified file hashes to EDR blocklists "
            "and monitor for suspicious registry modifications."
        )

    # Correlated CVEs
    recs.append(
        "**PRIORITY 3 — Review Correlated CVEs:** CVEs sharing ATT&CK techniques, CWEs, or "
        "PoC sources may indicate campaign-level targeting. Review correlated clusters."
    )

    if not recs:
        recs.append("Continue monitoring threat feeds. No urgent actions required this period.")

    return "\n\n".join(recs)
