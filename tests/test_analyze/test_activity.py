"""Tests for aiir2.analyze.activity."""

from __future__ import annotations

from datetime import datetime, timezone

from aiir2.analyze.activity import analyze_activity
from aiir2.models import (
    Action,
    ActivityAnalysis,
    ParticipantActivity,
    ProcessedExport,
    ProcessedMessage,
)


def _make_export(nonce: str = "def456") -> ProcessedExport:
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
                text=f"<user_message_{nonce}>Checking logs</user_message_{nonce}>",
            ),
        ],
        sanitization_nonce=nonce,
    )


def test_analyze_activity(mocker):
    """analyze_activity passes prompt and model to complete_structured."""
    expected = ActivityAnalysis(
        incident_id="INC-001",
        channel="#test-incident",
        participants=[
            ParticipantActivity(
                user_name="alice",
                role_hint="Lead Responder",
                actions=[
                    Action(
                        timestamp="2026-01-01T09:00:00Z",
                        purpose="Check server logs",
                        method="kubectl logs",
                        findings="Found OOM errors",
                    ),
                ],
            ),
        ],
    )
    mock_client = mocker.MagicMock()
    mock_client.complete_structured.return_value = expected

    export = _make_export()
    result = analyze_activity(export, mock_client)

    assert result is expected
    assert len(result.participants) == 1
    assert result.participants[0].user_name == "alice"
    mock_client.complete_structured.assert_called_once()

    args = mock_client.complete_structured.call_args
    system_prompt = args[0][0]
    user_prompt = args[0][1]
    schema = args[0][2]

    assert "incident" in system_prompt.lower()
    assert "def456" in system_prompt  # nonce present
    assert "#test-incident" in user_prompt
    assert schema is ActivityAnalysis


def test_analyze_activity_generates_nonce_when_empty(mocker):
    """When sanitization_nonce is empty, a fallback nonce is generated."""
    mock_client = mocker.MagicMock()
    mock_client.complete_structured.return_value = ActivityAnalysis(
        incident_id="INC-001",
        channel="#test",
        participants=[],
    )

    export = _make_export(nonce="")
    export.sanitization_nonce = ""
    analyze_activity(export, mock_client)

    args = mock_client.complete_structured.call_args
    system_prompt = args[0][0]
    assert "user_message_" in system_prompt
