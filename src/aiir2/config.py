"""Configuration for ai-ir2 Gemini integration."""

from __future__ import annotations

from pydantic import Field
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

    model_config = {"env_prefix": "AIIR2_", "env_file": ".env", "extra": "ignore"}


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
