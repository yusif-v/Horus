"""PoC verification engine — automated confidence scoring.

Scores each PoC 0-100 based on:
  - CVE ID presence in description (40 pts)
  - Repository freshness (20 pts)
  - Star count (15 pts)
  - URL/repo quality (10 pts)
  - Description quality (10 pts)
  - NVD cross-reference (5 pts)
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

# ── Scoring weights ──────────────────────────────────────────────────────

WEIGHTS = {
    "cve_presence": 40,
    "freshness": 20,
    "stars": 15,
    "url_quality": 10,
    "description": 10,
    "nvd_crossref": 5,
}

# ── Individual scorers ───────────────────────────────────────────────────


def _score_cve_presence(poc: Any) -> tuple[int, str]:
    """Does the description mention the CVE ID the PoC claims to be for?"""
    if not poc.description or not poc.cve_refs:
        return 0, "no_description_or_refs"
    desc_upper = poc.description.upper()
    for cve in poc.cve_refs:
        if cve.upper() in desc_upper:
            return WEIGHTS["cve_presence"], "cve_in_description"
    # Check if any CVE pattern appears in description
    found = CVE_PATTERN.findall(desc_upper)
    if found:
        return WEIGHTS["cve_presence"] // 2, "cve_mentioned_different"
    return 0, "cve_not_in_description"


def _score_freshness(poc: Any) -> tuple[int, str]:
    """Is the repo actively maintained / recently created?"""
    if not poc.repo_created_at:
        return WEIGHTS["freshness"] // 2, "unknown_freshness"
    try:
        created = datetime.fromisoformat(poc.repo_created_at.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return 0, "invalid_date"
    now = datetime.now(timezone.utc)
    age_days = (now - created).days
    if age_days <= 30:
        return WEIGHTS["freshness"], "very_recent"
    if age_days <= 90:
        return int(WEIGHTS["freshness"] * 0.75), "recent"
    if age_days <= 365:
        return int(WEIGHTS["freshness"] * 0.5), "moderate"
    return int(WEIGHTS["freshness"] * 0.25), "old"


def _score_stars(poc: Any) -> tuple[int, str]:
    """GitHub/GitLab star count as community validation."""
    stars = poc.stars
    if stars is None:
        return 0, "no_stars"
    if stars >= 1000:
        return WEIGHTS["stars"], "very_popular"
    if stars >= 100:
        return int(WEIGHTS["stars"] * 0.8), "popular"
    if stars >= 10:
        return int(WEIGHTS["stars"] * 0.5), "some_stars"
    return int(WEIGHTS["stars"] * 0.2), "few_stars"


def _score_url_quality(poc: Any) -> tuple[int, str]:
    """Is the URL a real code repo or just a reference?"""
    url = (poc.url or "").lower()
    if not url:
        return 0, "no_url"
    # Code repos
    if any(h in url for h in ("github.com/", "gitlab.com/", "codeberg.org/")):
        return WEIGHTS["url_quality"], "code_repo"
    # Exploit databases
    if "exploit-db.com" in url:
        return int(WEIGHTS["url_quality"] * 0.8), "exploit_db"
    # Pastebin / gists (lower trust)
    if any(h in url for h in ("pastebin.com", "gist.github.com")):
        return int(WEIGHTS["url_quality"] * 0.4), "paste_reference"
    # Everything else (blog, tweet, etc)
    return int(WEIGHTS["url_quality"] * 0.2), "other"


def _score_description(poc: Any) -> tuple[int, str]:
    """Does the PoC have a meaningful description?"""
    desc = (poc.description or "").strip()
    if not desc:
        return 0, "no_description"
    if len(desc) >= 100:
        return WEIGHTS["description"], "detailed"
    if len(desc) >= 30:
        return int(WEIGHTS["description"] * 0.6), "brief"
    return int(WEIGHTS["description"] * 0.2), "minimal"


def _score_nvd_crossref(poc: Any, known_cve_ids: set[str] | None = None) -> tuple[int, str]:
    """Does the linked CVE exist in NVD (our authoritative source)?"""
    if not poc.cve_refs:
        return 0, "no_refs"
    if known_cve_ids is not None:
        for cve in poc.cve_refs:
            if cve.upper() in known_cve_ids:
                return WEIGHTS["nvd_crossref"], "in_nvd"
        return 0, "not_in_nvd"
    # Without DB check, assume medium if refs exist
    return WEIGHTS["nvd_crossref"] // 2, "unverified"


# ── Public API ────────────────────────────────────────────────────────────


def verify_poc(poc: Any, known_cve_ids: set[str] | None = None) -> dict[str, Any]:
    """Score a single PoC. Returns {score, grade, factors}."""
    factors: dict[str, str] = {}
    total = 0

    score, reason = _score_cve_presence(poc)
    total += score
    factors["cve_presence"] = reason

    score, reason = _score_freshness(poc)
    total += score
    factors["freshness"] = reason

    score, reason = _score_stars(poc)
    total += score
    factors["stars"] = reason

    score, reason = _score_url_quality(poc)
    total += score
    factors["url_quality"] = reason

    score, reason = _score_description(poc)
    total += score
    factors["description"] = reason

    score, reason = _score_nvd_crossref(poc, known_cve_ids)
    total += score
    factors["nvd_crossref"] = reason

    return {
        "score": min(total, 100),
        "grade": _grade(total),
        "factors": factors,
    }


def _grade(score: int) -> str:
    if score >= 80:
        return "A"
    if score >= 60:
        return "B"
    if score >= 40:
        return "C"
    if score >= 20:
        return "D"
    return "F"


def verify_pocs(
    pocs: list[Any],
    conn: Any = None,
) -> list[dict[str, Any]]:
    """Score multiple PoCs. Uses DB connection for NVD cross-ref if provided."""
    known_cves: set[str] | None = None
    if conn is not None:
        known_cves = {row[0] for row in conn.execute("SELECT id FROM cve")}
    return [verify_poc(poc, known_cves) for poc in pocs]
