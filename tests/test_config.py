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
