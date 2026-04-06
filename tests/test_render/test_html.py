"""Tests for the self-contained HTML report renderer."""

from __future__ import annotations

import re

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
from aiir2.render.html import render_html


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_summary() -> IncidentSummary:
    return IncidentSummary(
        title="Database Outage in Production",
        severity="High",
        affected_systems=["db-primary"],
        timeline=[
            TimelineEvent(timestamp="09:55", actor="alice", event="Reported outage"),
        ],
        root_cause="Connection pool exhaustion.",
        resolution="Restarted pool.",
        summary="Production database became unreachable.",
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
                        purpose="Report",
                        method="Slack",
                        findings="Down",
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
                description="Escalated",
            ),
        ],
    )


def _make_review() -> IncidentReview:
    return IncidentReview(
        incident_id="abc123",
        channel="#inc-db",
        overall_score="good",
        phases=[
            ResponsePhase(phase="detection", estimated_duration="~5m", quality="good"),
        ],
        communication=CommunicationAssessment(overall="Good"),
        strengths=["Fast"],
        improvements=["Docs"],
        checklist=[ChecklistItem(item="Write runbook", priority="high")],
    )


def _make_tactics() -> list[Tactic]:
    return [
        Tactic(
            id="tac-001",
            title="Pool Check",
            purpose="Find leaks",
            category="database-analysis",
            tools=["psql"],
            procedure="SELECT * FROM pg_stat_activity;",
            observations="Look for idle sessions.",
            tags=["postgres"],
            confidence="confirmed",
            evidence="Shared output",
            source=TacticSource(channel="#inc-db", participants=["bob"]),
            created_at="2026-03-19",
        ),
    ]


def _render() -> str:
    return render_html(
        incident_id="abc123",
        channel="#inc-db",
        summary=_make_summary(),
        activity=_make_activity(),
        roles=_make_roles(),
        review=_make_review(),
        tactics=_make_tactics(),
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_render_html_self_contained():
    """Output must not reference any external URLs (no CDN links)."""
    html = _render()
    # Match http:// or https:// that are NOT inside Jinja comments or our own data.
    # The only URLs allowed are in the rendered data itself (which is test-controlled).
    external_urls = re.findall(r'(?:src|href)=["\']https?://', html)
    assert external_urls == [], f"Found external URLs: {external_urls}"


def test_render_html_contains_tabs():
    """Tab navigation elements must be present."""
    html = _render()
    assert 'data-tab="summary"' in html
    assert 'data-tab="activity"' in html
    assert 'data-tab="roles"' in html
    assert 'data-tab="review"' in html
    assert 'data-tab="tactics"' in html


def test_render_html_contains_data():
    """Incident ID and channel must appear in the rendered output."""
    html = _render()
    assert "abc123" in html
    assert "#inc-db" in html
    assert "Database Outage in Production" in html


def test_render_html_timezone_utc():
    """Default UTC timezone produces 'UTC' in generated_at."""
    html = render_html(
        incident_id="abc123",
        channel="#inc-db",
        summary=_make_summary(),
        activity=_make_activity(),
        roles=_make_roles(),
        review=_make_review(),
        tactics=_make_tactics(),
        tz="UTC",
    )
    assert "UTC" in html


def test_render_html_timezone_asia_tokyo():
    """Asia/Tokyo timezone produces +09:00 offset in output."""
    html = render_html(
        incident_id="abc123",
        channel="#inc-db",
        summary=_make_summary(),
        activity=_make_activity(),
        roles=_make_roles(),
        review=_make_review(),
        tactics=_make_tactics(),
        tz="Asia/Tokyo",
    )
    assert "Asia/Tokyo" in html
    assert "+09:00" in html
