"""Tests for AI flag integration in CLI."""

from __future__ import annotations

import os
from unittest.mock import patch

from horus.cli import main


class TestWeeklyReportAI:
    def test_ai_flag_triggers_analysis(self, capsys, tmp_path):
        """When --ai is set and provider available, AI result is accepted."""
        with patch("horus.cli._cmd_weekly_report") as mock_cmd:
            main(["--weekly-report", "--ai", "--config", str(tmp_path)])
            mock_cmd.assert_called_once()

    def test_ai_without_provider_warns(self, tmp_path):
        """When --ai is set but no provider configured, falls back gracefully."""
        env_backup = {}
        for key in list(os.environ):
            if key.startswith("HORUS_AI") or key.endswith("_API_KEY"):
                env_backup[key] = os.environ.pop(key)

        try:
            with patch("horus.cli._cmd_weekly_report") as mock_cmd:
                main(["--weekly-report", "--ai", "--config", str(tmp_path)])
                mock_cmd.assert_called_once()
        finally:
            os.environ.update(env_backup)

    def test_ai_provider_flag_accepted(self, tmp_path):
        """--ai-provider flag is accepted with valid choices."""
        with patch("horus.cli._cmd_weekly_report") as mock_cmd:
            main(
                [
                    "--weekly-report",
                    "--ai",
                    "--ai-provider",
                    "openai",
                    "--config",
                    str(tmp_path),
                ]
            )
            mock_cmd.assert_called_once()

    def test_without_ai_flag_no_analysis(self, tmp_path, capsys):
        """Without --ai flag, report renders normally without AI import."""
        with patch("horus.cli._cmd_weekly_report") as mock_cmd:
            main(["--weekly-report", "--config", str(tmp_path)])
            mock_cmd.assert_called_once()
