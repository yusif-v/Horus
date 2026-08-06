"""Tests for MITRE ATT&CK technique mapping."""

from __future__ import annotations

from horus.core.attack_mapping import (
    ATTACK_TO_TAGS,
    TAG_TO_ATTACK,
    get_all_techniques,
    get_attck_for_cve,
    get_attck_for_tag,
)
from horus.core.vocab import ATTACK_TAGS

# ── Coverage ───────────────────────────────────────────────────────────────


class TestTagCoverage:
    """Every tag in ATTACK_TAGS must have an ATT&CK mapping."""

    def test_all_tags_mapped(self):
        for tag in ATTACK_TAGS:
            assert tag in TAG_TO_ATTACK, f"Tag '{tag}' is missing from TAG_TO_ATTACK"

    def test_no_extra_tags_in_mapping(self):
        for tag in TAG_TO_ATTACK:
            assert tag in ATTACK_TAGS, f"TAG_TO_ATTACK has unknown tag '{tag}'"

    def test_each_tag_has_at_least_one_technique(self):
        for tag, techniques in TAG_TO_ATTACK.items():
            assert len(techniques) >= 1, f"Tag '{tag}' has no techniques"

    def test_technique_entries_have_id_and_name(self):
        for tag, techniques in TAG_TO_ATTACK.items():
            for t in techniques:
                assert "id" in t, f"Tag '{tag}' technique missing 'id'"
                assert "name" in t, f"Tag '{tag}' technique missing 'name'"
                assert t["id"].startswith("T"), (
                    f"Tag '{tag}' technique id '{t['id']}' doesn't start with T"
                )


# ── Lookup functions ──────────────────────────────────────────────────────


class TestLookups:
    def test_get_attck_for_known_tag(self):
        result = get_attck_for_tag("rce")
        assert len(result) >= 1
        assert result[0]["id"] == "T1190"

    def test_get_attck_for_unknown_tag(self):
        assert get_attck_for_tag("nonexistent") == []

    def test_get_attck_for_cve_deduplicates(self):
        # "rce" maps to T1190 and T1059; "sql-injection" also maps to T1190
        # The merged result should have T1190 only once
        result = get_attck_for_cve(["rce", "sql-injection"])
        ids = [t["id"] for t in result]
        assert "T1190" in ids
        assert "T1059" in ids
        assert len(ids) == len(set(ids)), "Duplicate technique IDs found"

    def test_get_attck_for_cve_empty(self):
        assert get_attck_for_cve([]) == []

    def test_get_attck_for_cve_preserves_order(self):
        result = get_attck_for_cve(["rce"])
        ids = [t["id"] for t in result]
        assert ids == ["T1190", "T1059"]

    def test_get_all_techniques_sorted(self):
        techniques = get_all_techniques()
        ids = [t["id"] for t in techniques]
        assert ids == sorted(ids)
        assert len(ids) == len(set(ids))

    def test_get_all_techniques_nonempty(self):
        assert len(get_all_techniques()) > 0


# ── Reverse lookup ────────────────────────────────────────────────────────


class TestReverseLookup:
    def test_attack_to_tags_populated(self):
        assert len(ATTACK_TO_TAGS) > 0

    def test_reverse_lookup_consistent(self):
        # Every technique_id in ATTACK_TO_TAGS must trace back to tags
        # that include it in TAG_TO_ATTACK
        for tid, tags in ATTACK_TO_TAGS.items():
            for tag in tags:
                technique_ids = [t["id"] for t in TAG_TO_ATTACK[tag]]
                assert tid in technique_ids, (
                    f"Reverse lookup says '{tid}' ← '{tag}', but TAG_TO_ATTACK['{tag}'] = {technique_ids}"
                )

    def test_specific_reverse_lookup(self):
        # T1190 is mapped from rce, sql-injection, ssrf, xxe, file-inclusion
        assert "T1190" in ATTACK_TO_TAGS
        tags = ATTACK_TO_TAGS["T1190"]
        assert "rce" in tags
        assert "sql-injection" in tags


# ── Persistence (integration) ────────────────────────────────────────────


class TestPersistAttackTechniques:
    def test_persist_and_read(self, tmp_path):
        import horus.storage.db as db_module

        db_module.DB_PATH = tmp_path / "test.db"
        db_module.initialize()
        from horus.core.merge import persist_attack_techniques
        from horus.storage.db import connect

        with connect() as conn:
            now = "2026-01-01T00:00:00Z"
            conn.execute(
                "INSERT INTO cve (id, first_seen, last_seen) VALUES (?, ?, ?)",
                ("CVE-2026-0001", now, now),
            )
            persist_attack_techniques(conn, "CVE-2026-0001", ["rce", "lpe"])

            rows = conn.execute(
                "SELECT technique_id, technique_name FROM cve_attack_technique"
                " WHERE cve_id = ? ORDER BY technique_id",
                ("CVE-2026-0001",),
            ).fetchall()
            ids = [r[0] for r in rows]
            assert "T1190" in ids  # from rce
            assert "T1068" in ids  # from lpe
            assert "T1059" in ids  # from rce

    def test_persist_replaces_existing(self, tmp_path):
        import horus.storage.db as db_module

        db_module.DB_PATH = tmp_path / "test2.db"
        db_module.initialize()
        from horus.core.merge import persist_attack_techniques
        from horus.storage.db import connect

        with connect() as conn:
            now = "2026-01-01T00:00:00Z"
            conn.execute(
                "INSERT INTO cve (id, first_seen, last_seen) VALUES (?, ?, ?)",
                ("CVE-2026-0002", now, now),
            )
            persist_attack_techniques(conn, "CVE-2026-0002", ["rce"])
            count_after_rce = conn.execute(
                "SELECT COUNT(*) FROM cve_attack_technique WHERE cve_id = ?",
                ("CVE-2026-0002",),
            ).fetchone()[0]

            # Re-persist with a different tag set — old rows should be gone
            persist_attack_techniques(conn, "CVE-2026-0002", ["dos"])
            rows = conn.execute(
                "SELECT technique_id FROM cve_attack_technique WHERE cve_id = ?",
                ("CVE-2026-0002",),
            ).fetchall()
            ids = [r[0] for r in rows]
            assert all(t in ("T1498", "T1499") for t in ids)
            assert len(ids) < count_after_rce or ids != ["T1190", "T1059"][: len(ids)]
