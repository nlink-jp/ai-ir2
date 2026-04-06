"""Configuration for ai-ir2 Gemini integration."""

from __future__ import annotations

from zoneinfo import ZoneInfo

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings


class GeminiConfig(BaseSettings):
    """Vertex AI Gemini configuration loaded from environment variables.

    All settings use the ``AIIR2_`` prefix and can be overridden via a
    ``.env`` file in the working directory.

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
    # Filter out empty overrides so env vars take precedence.
    filtered = {k: v for k, v in overrides.items() if v}
    config = GeminiConfig(**filtered)
    if not config.project:
        raise ValueError(
            "GCP project is required. Set AIIR2_PROJECT environment variable "
            "or pass --project flag."
        )
    return config
