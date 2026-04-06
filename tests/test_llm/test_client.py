"""Tests for aiir2.llm.client module."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from pydantic import BaseModel

from aiir2.config import GeminiConfig
from aiir2.llm.client import GeminiClient


class SimpleResponse(BaseModel):
    """Simple model for testing structured output."""

    answer: str


def _make_config() -> GeminiConfig:
    """Create a minimal GeminiConfig for tests."""
    return GeminiConfig(
        project="test-project",
        location="us-central1",
        model="gemini-2.5-flash",
    )


def _mock_response(text: str) -> MagicMock:
    """Create a mock Gemini response with the given text."""
    resp = MagicMock()
    resp.text = text
    return resp


@patch("aiir2.llm.client.genai.Client")
class TestGeminiClient:
    """Tests for GeminiClient."""

    def test_complete_structured_returns_model(self, mock_client_cls: MagicMock) -> None:
        """complete_structured parses JSON response into a Pydantic model."""
        mock_client = mock_client_cls.return_value
        mock_client.models.generate_content.return_value = _mock_response(
            '{"answer": "42"}'
        )

        client = GeminiClient(_make_config())
        result = client.complete_structured(
            system_prompt="You are helpful.",
            user_prompt="What is the answer?",
            schema=SimpleResponse,
        )

        assert isinstance(result, SimpleResponse)
        assert result.answer == "42"

        # Verify generate_content was called once
        mock_client.models.generate_content.assert_called_once()
        call_kwargs = mock_client.models.generate_content.call_args
        assert call_kwargs.kwargs["model"] == "gemini-2.5-flash"
        assert call_kwargs.kwargs["contents"] == "What is the answer?"

    def test_complete_text_returns_string(self, mock_client_cls: MagicMock) -> None:
        """complete_text returns raw text from the API response."""
        mock_client = mock_client_cls.return_value
        mock_client.models.generate_content.return_value = _mock_response(
            "Hello, world!"
        )

        client = GeminiClient(_make_config())
        result = client.complete_text(
            system_prompt="You are a translator.",
            user_prompt="Translate this.",
        )

        assert result == "Hello, world!"
        mock_client.models.generate_content.assert_called_once()

    def test_retry_on_rate_limit(self, mock_client_cls: MagicMock) -> None:
        """Retries on 429 rate limit error and succeeds on second attempt."""
        mock_client = mock_client_cls.return_value
        mock_client.models.generate_content.side_effect = [
            Exception("429 Resource has been exhausted"),
            _mock_response("success"),
        ]

        client = GeminiClient(_make_config())
        with patch("aiir2.llm.client.time.sleep") as mock_sleep:
            result = client.complete_text(
                system_prompt="system",
                user_prompt="user",
            )

        assert result == "success"
        assert mock_client.models.generate_content.call_count == 2
        mock_sleep.assert_called_once()

    def test_non_retryable_error_raises_immediately(
        self, mock_client_cls: MagicMock
    ) -> None:
        """Non-retryable errors are raised without retry."""
        mock_client = mock_client_cls.return_value
        mock_client.models.generate_content.side_effect = ValueError(
            "Invalid model name"
        )

        client = GeminiClient(_make_config())
        with patch("aiir2.llm.client.time.sleep") as mock_sleep:
            with pytest.raises(ValueError, match="Invalid model name"):
                client.complete_text(
                    system_prompt="system",
                    user_prompt="user",
                )

        # Should not retry — only one call
        assert mock_client.models.generate_content.call_count == 1
        mock_sleep.assert_not_called()
