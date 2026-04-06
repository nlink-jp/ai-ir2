"""Tests for aiir2.config module."""

import os

import pytest

from aiir2.config import GeminiConfig, get_gemini_config


def test_config_defaults():
    """Default values are set for location and model."""
    config = GeminiConfig(project="test-project")
    assert config.project == "test-project"
    assert config.location == "us-central1"
    assert config.model == "gemini-2.5-flash"


def test_config_from_env(monkeypatch):
    """Config loads from AIIR2_ environment variables."""
    monkeypatch.setenv("AIIR2_PROJECT", "env-project")
    monkeypatch.setenv("AIIR2_LOCATION", "asia-northeast1")
    monkeypatch.setenv("AIIR2_MODEL", "gemini-2.5-pro")
    config = GeminiConfig()
    assert config.project == "env-project"
    assert config.location == "asia-northeast1"
    assert config.model == "gemini-2.5-pro"


def test_get_gemini_config_with_overrides(monkeypatch):
    """CLI overrides take precedence over env vars."""
    monkeypatch.setenv("AIIR2_PROJECT", "env-project")
    config = get_gemini_config(project="cli-project")
    assert config.project == "cli-project"


def test_get_gemini_config_empty_override_uses_env(monkeypatch):
    """Empty CLI override falls back to env var."""
    monkeypatch.setenv("AIIR2_PROJECT", "env-project")
    config = get_gemini_config(project="")
    assert config.project == "env-project"


def test_get_gemini_config_missing_project_raises(monkeypatch):
    """Missing project raises ValueError."""
    monkeypatch.delenv("AIIR2_PROJECT", raising=False)
    with pytest.raises(ValueError, match="GCP project is required"):
        get_gemini_config()


def test_config_timezone_default():
    """Default timezone is UTC."""
    config = GeminiConfig(project="test-project")
    assert config.timezone == "UTC"


def test_config_timezone_from_env(monkeypatch):
    """Timezone loads from AIIR2_TIMEZONE environment variable."""
    monkeypatch.setenv("AIIR2_PROJECT", "test-project")
    monkeypatch.setenv("AIIR2_TIMEZONE", "Asia/Tokyo")
    config = GeminiConfig()
    assert config.timezone == "Asia/Tokyo"


def test_config_timezone_cli_override(monkeypatch):
    """CLI --timezone override takes precedence."""
    monkeypatch.setenv("AIIR2_PROJECT", "test-project")
    config = get_gemini_config(project="test-project", timezone="America/New_York")
    assert config.timezone == "America/New_York"


def test_config_timezone_invalid_raises():
    """Invalid timezone raises ValueError."""
    with pytest.raises(ValueError, match="Invalid timezone"):
        GeminiConfig(project="test-project", timezone="Not/A/Timezone")
