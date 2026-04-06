"""Tests for aiir2.analyze.roles."""

from __future__ import annotations

from datetime import datetime, timezone

from aiir2.analyze.roles import analyze_roles
from aiir2.models import (
    ParticipantRole,
    ProcessedExport,
    ProcessedMessage,
    Relationship,
    RoleAnalysis,
)


def _make_export(nonce: str = "ghi789") -> ProcessedExport:
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
                text=f"<user_message_{nonce}>I'm taking IC role</user_message_{nonce}>",
            ),
        ],
        sanitization_nonce=nonce,
    )


def test_analyze_roles(mocker):
    """analyze_roles passes prompt and model to complete_structured."""
    expected = RoleAnalysis(
        incident_id="INC-001",
        channel="#test-incident",
        participants=[
            ParticipantRole(
                user_name="alice",
                inferred_role="Incident Commander",
                confidence="high",
                evidence=["Stated 'I'm taking IC role'"],
            ),
        ],
        relationships=[
            Relationship(
                from_user="bob",
                to_user="alice",
                relationship_type="reports_to",
                description="Bob reported status updates to Alice",
            ),
        ],
    )
    mock_client = mocker.MagicMock()
    mock_client.complete_structured.return_value = expected

    export = _make_export()
    result = analyze_roles(export, mock_client)

    assert result is expected
    assert len(result.participants) == 1
    assert result.participants[0].inferred_role == "Incident Commander"
    assert len(result.relationships) == 1
    mock_client.complete_structured.assert_called_once()

    args = mock_client.complete_structured.call_args
    system_prompt = args[0][0]
    user_prompt = args[0][1]
    schema = args[0][2]

    assert "role" in system_prompt.lower()
    assert "ghi789" in system_prompt  # nonce present
    assert "#test-incident" in user_prompt
    assert schema is RoleAnalysis


def test_analyze_roles_generates_nonce_when_empty(mocker):
    """When sanitization_nonce is empty, a fallback nonce is generated."""
    mock_client = mocker.MagicMock()
    mock_client.complete_structured.return_value = RoleAnalysis(
        incident_id="INC-001",
        channel="#test",
        participants=[],
        relationships=[],
    )

    export = _make_export(nonce="")
    export.sanitization_nonce = ""
    analyze_roles(export, mock_client)

    args = mock_client.complete_structured.call_args
    system_prompt = args[0][0]
    assert "user_message_" in system_prompt
