"""Tests for the CLI entry point."""

from __future__ import annotations

from unittest.mock import patch

from click.testing import CliRunner

from aiir2 import __version__
from aiir2.cli import main


class TestHelp:
    """Tests for --help output."""

    def test_main_help(self):
        """Main --help shows group description."""
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "ai-ir2" in result.output

    def test_analyze_help(self):
        """analyze --help shows command description."""
        runner = CliRunner()
        result = runner.invoke(main, ["analyze", "--help"])
        assert result.exit_code == 0
        assert "Analyze" in result.output
        assert "--output-dir" in result.output
        assert "--lang" in result.output

    def test_config_show_help(self):
        """config show --help works."""
        runner = CliRunner()
        result = runner.invoke(main, ["config", "show", "--help"])
        assert result.exit_code == 0
        assert "Display" in result.output


class TestVersion:
    """Tests for --version output."""

    def test_version(self):
        """--version shows the package version."""
        runner = CliRunner()
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert __version__ in result.output


class TestConfigShow:
    """Tests for the config show command."""

    def test_config_show_defaults(self, monkeypatch):
        """config show displays default configuration."""
        # Clear env vars so defaults are used
        monkeypatch.delenv("AIIR2_PROJECT", raising=False)
        monkeypatch.delenv("AIIR2_LOCATION", raising=False)
        monkeypatch.delenv("AIIR2_MODEL", raising=False)

        runner = CliRunner()
        result = runner.invoke(main, ["config", "show"])
        assert result.exit_code == 0
        assert "Project:" in result.output
        assert "Location:" in result.output
        assert "Model:" in result.output

    def test_config_show_with_env(self, monkeypatch):
        """config show picks up environment variables."""
        monkeypatch.setenv("AIIR2_PROJECT", "my-test-project")
        monkeypatch.setenv("AIIR2_LOCATION", "asia-northeast1")
        monkeypatch.setenv("AIIR2_MODEL", "gemini-2.0-pro")

        runner = CliRunner()
        result = runner.invoke(main, ["config", "show"])
        assert result.exit_code == 0
        assert "my-test-project" in result.output
        assert "asia-northeast1" in result.output
        assert "gemini-2.0-pro" in result.output
