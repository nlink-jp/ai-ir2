"""Tests for the Markdown report renderer."""

from __future__ import annotations

from aiir2.models import (
    Action,
    ActivityAnalysis,
    ChecklistItem,
    CommunicationAssessment,
    IncidentReview,
    IncidentSummary,
    ParticipantActivity,
    ParticipantRole,
    Relationship,
    ResponsePhase,
    RoleAnalysis,
    Tactic,
    TacticSource,
    TimelineEvent,
)
from aiir2.render.markdown import render_markdown


# ---------------------------------------------------------------------------
# Fixtures (local to this module for explicitness)
# ---------------------------------------------------------------------------


def _make_summary() -> IncidentSummary:
    return IncidentSummary(
        title="Database Outage in Production",
        severity="High",
        affected_systems=["db-primary", "api-gateway"],
        timeline=[
            TimelineEvent(timestamp="09:55", actor="alice", event="Reported outage"),
            TimelineEvent(timestamp="09:56", actor="bob", event="Began triage"),
        ],
        root_cause="Connection pool exhaustion due to leaked connections.",
        resolution="Restarted the connection pool and deployed a fix.",
        summary="Production database became unreachable at 09:55 UTC.",
    )


def _make_activity() -> ActivityAnalysis:
    return ActivityAnalysis(
        incident_id="abc123",
        channel="#inc-db",
        participants=[
            ParticipantActivity(
                user_name="alice",
                role_hint="Reporter",
                actions=[
                    Action(
                        timestamp="09:55",
                        purpose="Report issue",
                        method="Slack message",
                        findings="Server unreachable",
                    ),
                ],
            ),
        ],
    )


def _make_roles() -> RoleAnalysis:
    return RoleAnalysis(
        incident_id="abc123",
        channel="#inc-db",
        participants=[
            ParticipantRole(
                user_name="alice",
                inferred_role="Reporter",
                confidence="high",
                evidence=["First to post"],
            ),
        ],
        relationships=[
            Relationship(
                from_user="alice",
                to_user="bob",
                relationship_type="escalated_to",
                description="Alice escalated to Bob",
            ),
        ],
    )


def _make_review() -> IncidentReview:
    return IncidentReview(
        incident_id="abc123",
        channel="#inc-db",
        overall_score="good",
        phases=[
            ResponsePhase(
                phase="detection",
                estimated_duration="~5 minutes",
                quality="good",
                notes="Rapid detection",
            ),
        ],
        communication=CommunicationAssessment(overall="Clear and timely."),
        strengths=["Quick escalation"],
        improvements=["Runbook was missing"],
        checklist=[ChecklistItem(item="Create runbook", priority="high")],
    )


def _make_tactics() -> list[Tactic]:
    return [
        Tactic(
            id="tac-001",
            title="Connection Pool Check",
            purpose="Identify leaked connections",
            category="database-analysis",
            tools=["psql", "pg_stat_activity"],
            procedure="Run SELECT * FROM pg_stat_activity;",
            observations="Look for idle-in-transaction sessions.",
            tags=["postgres"],
            confidence="confirmed",
            evidence="Output was shared in channel",
            source=TacticSource(channel="#inc-db", participants=["bob"]),
            created_at="2026-03-19",
        ),
    ]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_render_markdown_contains_title():
    """Summary title must appear in the rendered output."""
    md = render_markdown(
        incident_id="abc123",
        channel="#inc-db",
        summary=_make_summary(),
        activity=_make_activity(),
        roles=_make_roles(),
        review=_make_review(),
        tactics=_make_tactics(),
    )
    assert "Database Outage in Production" in md


def test_render_markdown_contains_timeline():
    """Timeline table headers must be present."""
    md = render_markdown(
        incident_id="abc123",
        channel="#inc-db",
        summary=_make_summary(),
        activity=_make_activity(),
        roles=_make_roles(),
        review=_make_review(),
        tactics=_make_tactics(),
    )
    assert "| Time | Actor | Event |" in md
    assert "alice" in md


def test_render_markdown_contains_review():
    """Process review section must be present."""
    md = render_markdown(
        incident_id="abc123",
        channel="#inc-db",
        summary=_make_summary(),
        activity=_make_activity(),
        roles=_make_roles(),
        review=_make_review(),
        tactics=_make_tactics(),
    )
    assert "## Process Review" in md
    assert "**Overall Score**: good" in md
    assert "Quick escalation" in md
    assert "Create runbook" in md


def test_render_markdown_timezone_utc():
    """Default UTC timezone produces 'UTC' label in Generated line."""
    md = render_markdown(
        incident_id="abc123",
        channel="#inc-db",
        summary=_make_summary(),
        activity=_make_activity(),
        roles=_make_roles(),
        review=_make_review(),
        tactics=_make_tactics(),
        tz="UTC",
    )
    # Should contain a Generated line with UTC
    assert "**Generated**:" in md
    assert "UTC" in md


def test_render_markdown_timezone_asia_tokyo():
    """Asia/Tokyo timezone produces +09:00 offset in Generated line."""
    md = render_markdown(
        incident_id="abc123",
        channel="#inc-db",
        summary=_make_summary(),
        activity=_make_activity(),
        roles=_make_roles(),
        review=_make_review(),
        tactics=_make_tactics(),
        tz="Asia/Tokyo",
    )
    assert "Asia/Tokyo" in md
    assert "+09:00" in md


def test_render_markdown_defangs_iocs():
    """IoCs embedded in narrative fields must be defanged."""
    summary = _make_summary()
    summary.root_cause = "Attacker used http://evil.com/payload to exploit the server at 192.168.1.50 directly"

    md = render_markdown(
        incident_id="abc123",
        channel="#inc-db",
        summary=summary,
        activity=_make_activity(),
        roles=_make_roles(),
        review=_make_review(),
        tactics=_make_tactics(),
    )
    # URL scheme must be defanged
    assert "hxxp://" in md
    assert "http://evil.com" not in md
    # IP must be defanged
    assert "192[.]168[.]1[.]50" in md
    assert "192.168.1.50" not in md
