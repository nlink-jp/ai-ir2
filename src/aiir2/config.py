"""Configuration for ai-ir2 Gemini integration."""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource


def _load_toml(tool_name: str) -> dict[str, Any]:
    """Load TOML config from ~/.config/<tool_name>/config.toml if it exists."""
    path = Path.home() / ".config" / tool_name / "config.toml"
    if not path.is_file():
        return {}
    with path.open("rb") as f:
        data = tomllib.load(f)
    flat: dict[str, Any] = {}
    if "gcp" in data and isinstance(data["gcp"], dict):
        if "project" in data["gcp"]:
            flat["project"] = data["gcp"]["project"]
        if "location" in data["gcp"]:
            flat["location"] = data["gcp"]["location"]
    if "model" in data and isinstance(data["model"], dict):
        model_section = data["model"]
        if "name" in model_section:
            flat["model"] = model_section["name"]
        for k, v in model_section.items():
            if k != "name":
                flat[k] = v
    for k, v in data.items():
        if k not in ("gcp", "model") and not isinstance(v, dict):
            flat[k] = v
    return flat


class GeminiConfig(BaseSettings):
    """Vertex AI Gemini configuration loaded from config file and environment variables.

    Authentication uses Application Default Credentials (ADC).
    Run ``gcloud auth application-default login`` to set up credentials.
    """

    project: str = Field(default="", description="GCP project ID")
    location: str = Field(default="us-central1", description="Vertex AI location")
    model: str = Field(default="gemini-2.5-flash", description="Gemini model name")
    timezone: str = Field(
        default="UTC",
        description="Timezone for report timestamps (e.g. Asia/Tokyo, UTC)",
    )

    model_config = {"env_prefix": "AIIR2_", "env_file": ".env", "extra": "ignore"}

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        """Priority: init (CLI flags) > env vars > .env > config.toml > defaults."""
        from pydantic_settings import InitSettingsSource

        toml_data = _load_toml("ai-ir2")
        toml_source = InitSettingsSource(settings_cls, init_kwargs=toml_data)
        return (init_settings, env_settings, dotenv_settings, toml_source, file_secret_settings)

    @field_validator("timezone")
    @classmethod
    def _validate_timezone(cls, v: str) -> str:
        """Ensure the timezone string is a valid IANA timezone name."""
        try:
            ZoneInfo(v)
        except (KeyError, Exception) as exc:
            raise ValueError(
                f"Invalid timezone: {v!r}. Use IANA timezone names "
                f"(e.g. 'UTC', 'Asia/Tokyo', 'America/New_York')."
            ) from exc
        return v


def get_gemini_config(**overrides: str) -> GeminiConfig:
    """Load Gemini config with optional CLI overrides.

    Args:
        **overrides: CLI flag values (e.g. project="my-project").
            Empty strings are ignored so that unset flags don't override
            environment variables.

    Returns:
        Validated GeminiConfig.

    Raises:
        ValueError: If project is not configured.
    """
    filtered = {k: v for k, v in overrides.items() if v}
    config = GeminiConfig(**filtered)
    if not config.project:
        raise ValueError(
            "GCP project is required. Set AIIR2_PROJECT environment variable "
            "or pass --project flag."
        )
    return config
