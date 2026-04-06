"""Tests for aiir2.analyze.reviewer."""

from __future__ import annotations

from aiir2.analyze.reviewer import review_incident
from aiir2.models import (
    ChecklistItem,
    CommunicationAssessment,
    IncidentReview,
    ResponsePhase,
    RoleClarity,
)


def _make_report_data() -> dict:
    """Create a minimal report dict for testing."""
    return {
        "incident_id": "INC-20260101-001",
        "metadata": {"channel": "#test-incident"},
        "summary": {
            "title": "Production outage",
            "severity": "high",
            "summary": "Server went down due to OOM.",
        },
        "activity": {
            "participants": [
                {
                    "user_name": "alice",
                    "role_hint": "IC",
                    "actions": [],
                },
            ],
        },
        "roles": {
            "participants": [
                {
                    "user_name": "alice",
                    "inferred_role": "Incident Commander",
                    "confidence": "high",
                },
            ],
        },
        "tactics": [],
    }


def test_review_incident(mocker):
    """review_incident passes prompt and model to complete_structured."""
    expected = IncidentReview(
        incident_id="INC-20260101-001",
        channel="#test-incident",
        overall_score="good",
        phases=[
            ResponsePhase(
                phase="detection",
                estimated_duration="~5 minutes",
                quality="good",
                notes="Quick detection via monitoring.",
            ),
        ],
        communication=CommunicationAssessment(
            overall="Clear communication throughout.",
        ),
        role_clarity=RoleClarity(
            ic_identified=True,
            ic_name="alice",
        ),
        strengths=["Fast detection"],
        improvements=["Document runbooks"],
        checklist=[
            ChecklistItem(item="Create runbook", priority="high"),
        ],
    )
    mock_client = mocker.MagicMock()
    mock_client.complete_structured.return_value = expected

    report_data = _make_report_data()
    result = review_incident(report_data, mock_client)

    assert result is expected
    assert result.overall_score == "good"
    assert result.incident_id == "INC-20260101-001"
    mock_client.complete_structured.assert_called_once()

    args = mock_client.complete_structured.call_args
    system_prompt = args[0][0]
    user_prompt = args[0][1]
    schema = args[0][2]

    assert "incident" in system_prompt.lower()
    assert "process" in system_prompt.lower()
    assert "#test-incident" in user_prompt
    assert schema is IncidentReview


def test_review_incident_fills_missing_fields(mocker):
    """review_incident fills incident_id and channel when LLM omits them."""
    mock_client = mocker.MagicMock()
    mock_client.complete_structured.return_value = IncidentReview(
        # LLM returned empty strings for these
        incident_id="",
        channel="",
        overall_score="adequate",
    )

    report_data = _make_report_data()
    result = review_incident(report_data, mock_client)

    assert result.incident_id == "INC-20260101-001"
    assert result.channel == "#test-incident"


def test_review_incident_uses_channel_fallback(mocker):
    """review_incident falls back to top-level channel key."""
    mock_client = mocker.MagicMock()
    mock_client.complete_structured.return_value = IncidentReview(
        incident_id="",
        channel="",
        overall_score="poor",
    )

    report_data = {
        "incident_id": "INC-002",
        "channel": "#fallback-channel",
        "summary": {},
        "activity": {},
        "roles": {},
        "tactics": [],
    }
    result = review_incident(report_data, mock_client)

    assert result.channel == "#fallback-channel"
