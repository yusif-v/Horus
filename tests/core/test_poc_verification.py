"""PoC verification engine — scoring contract tests.

Pins the weights, grade boundaries, and factor reasons so regressions
surface as test failures instead of silent drift.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

from horus.core.model import PoC
from horus.core.poc_verification import (
    _grade,
    _score_cve_presence,
    _score_description,
    _score_freshness,
    _score_nvd_crossref,
    _score_stars,
    _score_url_quality,
    verify_poc,
    verify_pocs,
)

# ── Helpers ────────────────────────────────────────────────────────────────


def _iso(days_ago: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat()


def _poc(**kw) -> PoC:
    defaults = {"url": "https://example.com", "source": "web"}
    defaults.update(kw)
    return PoC(**defaults)


# ── _score_cve_presence ───────────────────────────────────────────────────


class TestScoreCvePresence:
    def test_cve_ref_in_description_scores_full(self):
        poc = _poc(description="RCE for CVE-2026-0001 in Apache", cve_refs=["CVE-2026-0001"])
        score, reason = _score_cve_presence(poc)
        assert score == 40
        assert reason == "cve_in_description"

    def test_cve_pattern_but_not_ref_scores_half(self):
        poc = _poc(description="RCE for CVE-2026-9999", cve_refs=["CVE-2026-0001"])
        score, reason = _score_cve_presence(poc)
        assert score == 20
        assert reason == "cve_mentioned_different"

    def test_no_cve_mention_scores_zero(self):
        poc = _poc(description="some exploit", cve_refs=["CVE-2026-0001"])
        score, reason = _score_cve_presence(poc)
        assert score == 0
        assert reason == "cve_not_in_description"

    def test_no_description_scores_zero(self):
        poc = _poc(description=None, cve_refs=["CVE-2026-0001"])
        score, reason = _score_cve_presence(poc)
        assert score == 0
        assert reason == "no_description_or_refs"

    def test_no_cve_refs_scores_zero(self):
        poc = _poc(description="CVE-2026-0001 RCE", cve_refs=[])
        score, reason = _score_cve_presence(poc)
        assert score == 0
        assert reason == "no_description_or_refs"


# ── _score_freshness ──────────────────────────────────────────────────────


class TestScoreFreshness:
    def test_very_recent_scores_full(self):
        score, reason = _score_freshness(_poc(repo_created_at=_iso(5)))
        assert score == 20
        assert reason == "very_recent"

    def test_recent_scores_75_pct(self):
        score, reason = _score_freshness(_poc(repo_created_at=_iso(60)))
        assert score == 15
        assert reason == "recent"

    def test_moderate_scores_half(self):
        score, reason = _score_freshness(_poc(repo_created_at=_iso(200)))
        assert score == 10
        assert reason == "moderate"

    def test_old_scores_quarter(self):
        score, reason = _score_freshness(_poc(repo_created_at=_iso(500)))
        assert score == 5
        assert reason == "old"

    def test_unknown_scores_half(self):
        score, reason = _score_freshness(_poc(repo_created_at=None))
        assert score == 10
        assert reason == "unknown_freshness"

    def test_invalid_date_scores_zero(self):
        score, reason = _score_freshness(_poc(repo_created_at="not-a-date"))
        assert score == 0
        assert reason == "invalid_date"


# ── _score_stars ──────────────────────────────────────────────────────────


class TestScoreStars:
    def test_very_popular_scores_full(self):
        score, reason = _score_stars(_poc(stars=1500))
        assert score == 15
        assert reason == "very_popular"

    def test_popular_scores_80_pct(self):
        score, reason = _score_stars(_poc(stars=500))
        assert score == 12
        assert reason == "popular"

    def test_some_stars_scores_half(self):
        score, reason = _score_stars(_poc(stars=25))
        assert score == 7
        assert reason == "some_stars"

    def test_few_stars_scores_20_pct(self):
        score, reason = _score_stars(_poc(stars=3))
        assert score == 3
        assert reason == "few_stars"

    def test_zero_stars_scores_20_pct(self):
        score, reason = _score_stars(_poc(stars=0))
        assert score == 3
        assert reason == "few_stars"

    def test_none_scores_zero(self):
        score, reason = _score_stars(_poc(stars=None))
        assert score == 0
        assert reason == "no_stars"


# ── _score_url_quality ───────────────────────────────────────────────────


class TestScoreUrlQuality:
    def test_github_scores_full(self):
        score, reason = _score_url_quality(_poc(url="https://github.com/foo/bar"))
        assert score == 10
        assert reason == "code_repo"

    def test_gitlab_scores_full(self):
        score, reason = _score_url_quality(_poc(url="https://gitlab.com/foo/bar"))
        assert score == 10
        assert reason == "code_repo"

    def test_codeberg_scores_full(self):
        score, reason = _score_url_quality(_poc(url="https://codeberg.org/foo/bar"))
        assert score == 10
        assert reason == "code_repo"

    def test_exploit_db_scores_80_pct(self):
        score, reason = _score_url_quality(_poc(url="https://exploit-db.com/12345"))
        assert score == 8
        assert reason == "exploit_db"

    def test_pastebin_scores_40_pct(self):
        score, reason = _score_url_quality(_poc(url="https://pastebin.com/abc"))
        assert score == 4
        assert reason == "paste_reference"

    def test_gist_github_subdomain_scores_as_code_repo(self):
        # gist.github.com contains "github.com/" so it matches code_repo first
        score, reason = _score_url_quality(_poc(url="https://gist.github.com/abc"))
        assert score == 10
        assert reason == "code_repo"

    def test_other_scores_20_pct(self):
        score, reason = _score_url_quality(_poc(url="https://blog.example.com/post"))
        assert score == 2
        assert reason == "other"

    def test_empty_url_scores_zero(self):
        score, reason = _score_url_quality(_poc(url=""))
        assert score == 0
        assert reason == "no_url"

    def test_none_url_scores_zero(self):
        score, reason = _score_url_quality(_poc(url=None))
        assert score == 0
        assert reason == "no_url"


# ── _score_description ───────────────────────────────────────────────────


class TestScoreDescription:
    def test_detailed_scores_full(self):
        score, reason = _score_description(_poc(description="A" * 150))
        assert score == 10
        assert reason == "detailed"

    def test_brief_scores_60_pct(self):
        score, reason = _score_description(_poc(description="A" * 50))
        assert score == 6
        assert reason == "brief"

    def test_minimal_scores_20_pct(self):
        score, reason = _score_description(_poc(description="A" * 10))
        assert score == 2
        assert reason == "minimal"

    def test_empty_scores_zero(self):
        score, reason = _score_description(_poc(description=""))
        assert score == 0
        assert reason == "no_description"

    def test_none_scores_zero(self):
        score, reason = _score_description(_poc(description=None))
        assert score == 0
        assert reason == "no_description"

    def test_whitespace_scores_zero(self):
        score, reason = _score_description(_poc(description="   "))
        assert score == 0
        assert reason == "no_description"


# ── _score_nvd_crossref ──────────────────────────────────────────────────


class TestScoreNvdCrossref:
    def test_ref_in_nvd_scores_full(self):
        score, reason = _score_nvd_crossref(_poc(cve_refs=["CVE-2026-0001"]), {"CVE-2026-0001"})
        assert score == 5
        assert reason == "in_nvd"

    def test_ref_not_in_nvd_scores_zero(self):
        score, reason = _score_nvd_crossref(_poc(cve_refs=["CVE-2026-0001"]), {"CVE-2026-9999"})
        assert score == 0
        assert reason == "not_in_nvd"

    def test_unknown_set_with_refs_scores_half(self):
        score, reason = _score_nvd_crossref(_poc(cve_refs=["CVE-2026-0001"]), None)
        assert score == 2
        assert reason == "unverified"

    def test_no_refs_scores_zero(self):
        score, reason = _score_nvd_crossref(_poc(cve_refs=[]), {"CVE-2026-0001"})
        assert score == 0
        assert reason == "no_refs"


# ── Grade boundaries ─────────────────────────────────────────────────────


class TestGrade:
    def test_a_at_80(self):
        assert _grade(100) == "A"
        assert _grade(80) == "A"

    def test_b_at_60(self):
        assert _grade(79) == "B"
        assert _grade(60) == "B"

    def test_c_at_40(self):
        assert _grade(59) == "C"
        assert _grade(40) == "C"

    def test_d_at_20(self):
        assert _grade(39) == "D"
        assert _grade(20) == "D"

    def test_f_below_20(self):
        assert _grade(19) == "F"
        assert _grade(0) == "F"


# ── Composite: verify_poc ────────────────────────────────────────────────


class TestVerifyPoc:
    def test_high_quality_scores_a(self):
        poc = _poc(
            url="https://github.com/foo/bar",
            stars=1500,
            description="CVE-2026-0001 — " + "A" * 120,
            cve_refs=["CVE-2026-0001"],
            repo_created_at=_iso(5),
        )
        result = verify_poc(poc, {"CVE-2026-0001"})
        assert result["grade"] == "A"
        assert result["score"] >= 80

    def test_low_quality_scores_f_or_d(self):
        poc = _poc(
            url="https://blog.example.com/post",
            stars=None,
            description=None,
            cve_refs=[],
            repo_created_at=None,
        )
        result = verify_poc(poc)
        assert result["grade"] in ("D", "F")

    def test_result_has_expected_keys(self):
        result = verify_poc(_poc(description="x", cve_refs=["CVE-2026-0001"]), {"CVE-2026-0001"})
        assert set(result.keys()) == {"score", "grade", "factors"}
        assert isinstance(result["score"], int)
        assert isinstance(result["factors"], dict)
        assert set(result["factors"].keys()) == {
            "cve_presence",
            "freshness",
            "stars",
            "url_quality",
            "description",
            "nvd_crossref",
        }

    def test_score_capped_at_100(self):
        poc = _poc(
            url="https://github.com/foo/bar",
            stars=9999,
            description="CVE-2026-0001 — " + "Z" * 200,
            cve_refs=["CVE-2026-0001"],
            repo_created_at=_iso(1),
        )
        result = verify_poc(poc, {"CVE-2026-0001"})
        assert result["score"] == 100

    def test_all_factors_populated(self):
        result = verify_poc(_poc(cve_refs=["CVE-2026-0001"]), {"CVE-2026-0001"})
        assert all(v for v in result["factors"].values())


# ── verify_pocs (batch) ─────────────────────────────────────────────────


class TestVerifyPocs:
    def test_without_conn_no_nvd_lookup(self):
        pocs = [_poc(cve_refs=["CVE-2026-0001"])]
        results = verify_pocs(pocs)
        assert len(results) == 1
        assert results[0]["factors"]["nvd_crossref"] == "unverified"

    def test_with_mock_conn_queries_known_cves(self):
        conn = MagicMock()
        conn.execute.return_value = [("CVE-2026-0001",), ("CVE-2026-0002",)]
        pocs = [
            _poc(cve_refs=["CVE-2026-0001"]),
            _poc(cve_refs=["CVE-2026-9999"]),
        ]
        results = verify_pocs(pocs, conn)
        assert len(results) == 2
        assert results[0]["factors"]["nvd_crossref"] == "in_nvd"
        assert results[1]["factors"]["nvd_crossref"] == "not_in_nvd"
        conn.execute.assert_called_once_with("SELECT id FROM cve")

    def test_empty_list_returns_empty(self):
        assert verify_pocs([]) == []

    def test_result_count_matches_input(self):
        pocs = [_poc() for _ in range(5)]
        results = verify_pocs(pocs)
        assert len(results) == 5


# ── Pipeline wiring contract (what the persist step expects) ─────────────


class TestPipelineContract:
    def test_factors_are_json_serializable(self):
        """Pipeline stores factors as JSON — must survive json.dumps."""
        result = verify_poc(_poc(cve_refs=["CVE-2026-0001"]), {"CVE-2026-0001"})
        blob = json.dumps(result["factors"])
        restored = json.loads(blob)
        assert restored == result["factors"]

    def test_grade_is_single_char(self):
        result = verify_poc(_poc(cve_refs=["CVE-2026-0001"]))
        assert len(result["grade"]) == 1
        assert result["grade"] in "ABCDF"

    def test_score_is_int(self):
        result = verify_poc(_poc(cve_refs=["CVE-2026-0001"]))
        assert isinstance(result["score"], int)
