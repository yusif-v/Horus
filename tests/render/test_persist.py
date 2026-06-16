"""Tests for horus/render/persist.py — report file saving."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from unittest.mock import patch

from horus.render.persist import save_report


def test_save_report_creates_correct_path(tmp_path):
    when = datetime(2026, 3, 15, 12, 0, 0)
    with patch("horus.render.persist.REPORTS_DIR", tmp_path):
        path = save_report("# Test Report", fmt="md", when=when)
    assert path == tmp_path / "2026" / "03" / "2026-03-15.md"
    assert path.exists()
    assert path.read_text() == "# Test Report"


def test_save_report_txt_extension(tmp_path):
    when = datetime(2026, 1, 1)
    with patch("horus.render.persist.REPORTS_DIR", tmp_path):
        path = save_report("text report", fmt="txt", when=when)
    assert path.suffix == ".txt"


def test_save_report_returns_path_object(tmp_path):
    with patch("horus.render.persist.REPORTS_DIR", tmp_path):
        result = save_report("content")
    assert isinstance(result, Path)


def test_save_report_overwrites_same_day(tmp_path):
    when = datetime(2026, 6, 15, 10, 0, 0)
    with patch("horus.render.persist.REPORTS_DIR", tmp_path):
        path1 = save_report("first", fmt="md", when=when)
        path2 = save_report("second", fmt="md", when=when)
    assert path1 == path2
    assert path1.read_text() == "second"
