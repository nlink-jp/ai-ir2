"""Gemini LLM client for ai-ir2."""

from __future__ import annotations

import time
import logging
from typing import TypeVar

from google import genai
from google.genai import types
from pydantic import BaseModel

from aiir2.config import GeminiConfig

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)


class GeminiClient:
    """Vertex AI Gemini client with structured output and retry logic."""

    def __init__(self, config: GeminiConfig) -> None:
        self._client = genai.Client(
            vertexai=True,
            project=config.project,
            location=config.location,
        )
        self._model = config.model

    def complete_structured(
        self,
        system_prompt: str,
        user_prompt: str,
        schema: type[T],
    ) -> T:
        """Send a prompt and parse the response into a Pydantic model.

        Uses Gemini's response_schema for guaranteed valid JSON output.

        Args:
            system_prompt: System instruction.
            user_prompt: User message content.
            schema: Pydantic model class for response validation.

        Returns:
            Parsed Pydantic model instance.
        """
        response = self._call_with_retry(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            response_mime_type="application/json",
            response_schema=schema,
        )
        return schema.model_validate_json(response)

    def complete_text(
        self,
        system_prompt: str,
        user_prompt: str,
    ) -> str:
        """Send a prompt and return raw text response.

        Used for translation where structured output is not needed.

        Args:
            system_prompt: System instruction.
            user_prompt: User message content.

        Returns:
            Raw text response.
        """
        return self._call_with_retry(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
        )

    def _call_with_retry(
        self,
        system_prompt: str,
        user_prompt: str,
        response_mime_type: str | None = None,
        response_schema: type[BaseModel] | None = None,
        max_retries: int = 3,
        base_delay: float = 2.0,
    ) -> str:
        """Call Gemini API with exponential backoff on rate limit errors.

        Args:
            system_prompt: System instruction.
            user_prompt: User message content.
            response_mime_type: Optional MIME type (e.g. "application/json").
            response_schema: Optional Pydantic model for structured output.
            max_retries: Maximum retry attempts.
            base_delay: Base delay in seconds for exponential backoff.

        Returns:
            Response text from Gemini.

        Raises:
            Exception: If all retries are exhausted or a non-retryable error occurs.
        """
        config = types.GenerateContentConfig(
            system_instruction=system_prompt,
        )
        if response_mime_type:
            config.response_mime_type = response_mime_type
        if response_schema:
            config.response_schema = response_schema

        last_error: Exception | None = None
        for attempt in range(max_retries + 1):
            try:
                response = self._client.models.generate_content(
                    model=self._model,
                    contents=user_prompt,
                    config=config,
                )
                return response.text or ""
            except Exception as e:
                error_str = str(e)
                is_retryable = any(
                    keyword in error_str.lower()
                    for keyword in ("429", "resource_exhausted", "rate limit", "quota")
                )
                if not is_retryable or attempt == max_retries:
                    raise
                last_error = e
                delay = base_delay * (2**attempt)
                logger.warning(
                    "Gemini API rate limited (attempt %d/%d), retrying in %.1fs: %s",
                    attempt + 1,
                    max_retries + 1,
                    delay,
                    e,
                )
                time.sleep(delay)

        raise last_error  # type: ignore[misc]  # unreachable but satisfies type checker
