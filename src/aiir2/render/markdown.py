"""Markdown report renderer.

Produces a single combined Markdown document covering all analysis sections:
summary, participant activities, roles/relationships, process review, and
investigation tactics.  Narrative fields are passed through ``defang_text()``
to neutralise any IoCs the LLM may have re-introduced.
"""

from __future__ import annotations

from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from aiir2.models import (
    ActivityAnalysis,
    IncidentReview,
    IncidentSummary,
    RoleAnalysis,
    Tactic,
)
from aiir2.parser.defang import defang_text


def _escape_cell(text: str) -> str:
    """Escape pipe and newline characters for use inside a Markdown table cell."""
    return text.replace("|", "\\|").replace("\n", "<br>")


def _at(name: str) -> str:
    """Prefix *name* with ``@``, avoiding ``@@`` if it already starts with one."""
    return name if name.startswith("@") else f"@{name}"


def render_markdown(
    incident_id: str,
    channel: str,
    summary: IncidentSummary,
    activity: ActivityAnalysis,
    roles: RoleAnalysis,
    review: IncidentReview,
    tactics: list[Tactic],
    export_timestamp: str = "",
    tz: str = "UTC",
) -> str:
    """Render a complete analysis report as Markdown.

    Args:
        incident_id: Deterministic incident identifier.
        channel: Slack channel name.
        summary: Incident summary from the summarizer.
        activity: Per-participant activity analysis.
        roles: Role and relationship inference results.
        review: Process quality review.
        tactics: List of extracted investigation tactics.
        export_timestamp: Human-readable export timestamp.
        tz: IANA timezone name for the "Generated" timestamp.

    Returns:
        Markdown-formatted report string with all IoCs defanged.
    """
    zi = ZoneInfo(tz)
    now_dt = datetime.now(timezone.utc).astimezone(zi)
    tz_label = tz if tz == "UTC" else f"UTC{now_dt.strftime('%z')[:3]}:{now_dt.strftime('%z')[3:]} ({tz})"
    now = now_dt.strftime(f"%Y-%m-%d %H:%M:%S {tz_label}")
    lines: list[str] = [
        "# Incident Analysis Report",
        "",
        f"- **Channel**: {channel}",
        f"- **Incident ID**: {incident_id}",
        f"- **Generated**: {now}",
        f"- **Export timestamp**: {export_timestamp}",
        "",
        "---",
        "",
    ]

    # -- Summary Section -------------------------------------------------------
    lines.append(f"## Incident Summary")
    lines.append("")
    lines.append(f"### {summary.title}")
    lines.append("")
    lines.append(f"**Severity**: {summary.severity or 'Unknown'}")
    lines.append("")

    if summary.affected_systems:
        lines.append(
            f"**Affected Systems**: {', '.join(summary.affected_systems)}"
        )
        lines.append("")

    if summary.summary:
        lines.append(summary.summary)
        lines.append("")

    if summary.timeline:
        lines.append("### Timeline")
        lines.append("")
        lines.append("| Time | Actor | Event |")
        lines.append("|------|-------|-------|")
        for event in summary.timeline:
            lines.append(
                f"| {event.timestamp} | {event.actor} | {_escape_cell(event.event)} |"
            )
        lines.append("")

    if summary.root_cause:
        lines.append("### Root Cause")
        lines.append("")
        lines.append(summary.root_cause)
        lines.append("")

    if summary.resolution:
        lines.append("### Resolution")
        lines.append("")
        lines.append(summary.resolution)
        lines.append("")

    lines.append("---")
    lines.append("")

    # -- Activity Section ------------------------------------------------------
    lines.append("## Participant Activities")
    lines.append("")

    for participant in activity.participants:
        lines.append(f"### {_at(participant.user_name)} \u2014 {participant.role_hint}")
        lines.append("")

        if participant.actions:
            lines.append("| Time | Purpose | Method | Findings |")
            lines.append("|------|---------|--------|----------|")
            for action in participant.actions:
                lines.append(
                    f"| {action.timestamp}"
                    f" | {_escape_cell(action.purpose)}"
                    f" | {_escape_cell(action.method)}"
                    f" | {_escape_cell(action.findings)} |"
                )
            lines.append("")

    lines.append("---")
    lines.append("")

    # -- Roles Section ---------------------------------------------------------
    lines.append("## Roles and Relationships")
    lines.append("")

    if roles.participants:
        lines.append("### Participants")
        lines.append("")
        lines.append("| Participant | Role | Confidence | Evidence |")
        lines.append("|-------------|------|------------|----------|")
        for p in roles.participants:
            evidence_str = "; ".join(p.evidence) if p.evidence else ""
            lines.append(
                f"| {_at(p.user_name)}"
                f" | {p.inferred_role}"
                f" | {p.confidence}"
                f" | {_escape_cell(evidence_str)} |"
            )
        lines.append("")

    if roles.relationships:
        lines.append("### Relationships")
        lines.append("")
        lines.append("| From | Relationship | To | Description |")
        lines.append("|------|-------------|----|-------------|")
        for rel in roles.relationships:
            lines.append(
                f"| {_at(rel.from_user)}"
                f" | {rel.relationship_type}"
                f" | {_at(rel.to_user) if rel.to_user else ''}"
                f" | {_escape_cell(rel.description)} |"
            )
        lines.append("")

    lines.append("---")
    lines.append("")

    # -- Review Section --------------------------------------------------------
    lines.append("## Process Review")
    lines.append("")

    if review.overall_score:
        lines.append(f"**Overall Score**: {review.overall_score}")
        lines.append("")

    if review.phases:
        lines.append("### Response Phases")
        lines.append("")
        lines.append("| Phase | Duration | Quality | Notes |")
        lines.append("|-------|----------|---------|-------|")
        for phase in review.phases:
            lines.append(
                f"| {phase.phase}"
                f" | {phase.estimated_duration}"
                f" | {phase.quality}"
                f" | {_escape_cell(phase.notes)} |"
            )
        lines.append("")

    if (
        review.communication.overall
        or review.communication.delays_observed
        or review.communication.silos_observed
    ):
        lines.append("### Communication")
        lines.append("")
        if review.communication.overall:
            lines.append(review.communication.overall)
            lines.append("")
        if review.communication.delays_observed:
            lines.append("**Delays observed:**")
            for d in review.communication.delays_observed:
                lines.append(f"- {d}")
            lines.append("")
        if review.communication.silos_observed:
            lines.append("**Silos observed:**")
            for s in review.communication.silos_observed:
                lines.append(f"- {s}")
            lines.append("")

    if review.strengths:
        lines.append("### Strengths")
        lines.append("")
        for s in review.strengths:
            lines.append(f"- {s}")
        lines.append("")

    if review.improvements:
        lines.append("### Areas for Improvement")
        lines.append("")
        for imp in review.improvements:
            lines.append(f"- {imp}")
        lines.append("")

    if review.checklist:
        lines.append("### Action Items")
        lines.append("")
        for item in review.checklist:
            lines.append(f"- [ ] {item.item} ({item.priority})")
        lines.append("")

    lines.append("---")
    lines.append("")

    # -- Tactics Section -------------------------------------------------------
    if tactics:
        lines.append("## Investigation Tactics")
        lines.append("")

        for tactic in tactics:
            lines.append(f"### {tactic.title}")
            lines.append("")
            lines.append(f"- **Category**: {tactic.category}")
            lines.append(f"- **Confidence**: {tactic.confidence}")
            if tactic.tools:
                tools_str = ", ".join(f"`{t}`" for t in tactic.tools)
                lines.append(f"- **Tools**: {tools_str}")
            lines.append("")

            lines.append(f"**Purpose**: {tactic.purpose}")
            lines.append("")

            lines.append("**Procedure**:")
            lines.append("")
            lines.append(tactic.procedure)
            lines.append("")

            lines.append("**Observations**:")
            lines.append("")
            lines.append(tactic.observations)
            lines.append("")

            if tactic.tags:
                lines.append(f"**Tags**: {', '.join(tactic.tags)}")
                lines.append("")

    # Defang any IoCs the LLM may have re-introduced in narrative fields
    return defang_text("\n".join(lines))[0]
