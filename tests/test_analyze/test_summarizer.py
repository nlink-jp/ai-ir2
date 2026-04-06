"""Tests for aiir2.analyze.summarizer."""

from __future__ import annotations

from datetime import datetime, timezone

from aiir2.analyze.summarizer import summarize_incident
from aiir2.models import IncidentSummary, ProcessedExport, ProcessedMessage


def _make_export(nonce: str = "abc123") -> ProcessedExport:
    """Create a minimal ProcessedExport for testing."""
    return ProcessedExport(
        export_timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
        channel_name="#test-incident",
        messages=[
            ProcessedMessage(
                user_id="U001",
                user_name="alice",
                post_type="user",
                timestamp=datetime(2026, 1, 1, 9, 0, 0, tzinfo=timezone.utc),
                timestamp_unix="1735725600.000000",
                text=f"<user_message_{nonce}>Server is down</user_message_{nonce}>",
            ),
        ],
        sanitization_nonce=nonce,
    )


def test_summarize_incident(mocker):
    """summarize_incident passes prompt and model to complete_structured."""
    expected = IncidentSummary(
        title="Test Incident",
        summary="Test summary of the incident.",
    )
    mock_client = mocker.MagicMock()
    mock_client.complete_structured.return_value = expected

    export = _make_export()
    result = summarize_incident(export, mock_client)

    assert result is expected
    assert result.title == "Test Incident"
    mock_client.complete_structured.assert_called_once()

    # Verify arguments
    args = mock_client.complete_structured.call_args
    system_prompt = args[0][0]
    user_prompt = args[0][1]
    schema = args[0][2]

    assert "incident" in system_prompt.lower()
    assert "abc123" in system_prompt  # nonce present
    assert "#test-incident" in user_prompt
    assert schema is IncidentSummary


def test_summarize_incident_generates_nonce_when_empty(mocker):
    """When sanitization_nonce is empty, a fallback nonce is generated."""
    mock_client = mocker.MagicMock()
    mock_client.complete_structured.return_value = IncidentSummary(
        title="Fallback",
        summary="Test",
    )

    export = _make_export(nonce="")
    # Override nonce to empty
    export.sanitization_nonce = ""
    summarize_incident(export, mock_client)

    args = mock_client.complete_structured.call_args
    system_prompt = args[0][0]
    # Should contain a generated nonce (user_message_ tag), not empty
    assert "user_message_" in system_prompt
