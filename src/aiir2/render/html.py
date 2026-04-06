"""Self-contained HTML report renderer.

Uses a Jinja2 template with inline CSS and JS (no external CDN links) to
produce a single portable HTML file covering all analysis sections.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from jinja2 import Environment, FileSystemLoader

from aiir2.models import (
    ActivityAnalysis,
    IncidentReview,
    IncidentSummary,
    RoleAnalysis,
    Tactic,
)


_TEMPLATE_DIR = Path(__file__).parent / "templates"


def render_html(
    incident_id: str,
    channel: str,
    summary: IncidentSummary,
    activity: ActivityAnalysis,
    roles: RoleAnalysis,
    review: IncidentReview,
    tactics: list[Tactic],
    export_timestamp: str = "",
    lang: str = "en",
    tz: str = "UTC",
) -> str:
    """Render a complete analysis report as self-contained HTML.

    Args:
        incident_id: Deterministic incident identifier.
        channel: Slack channel name.
        summary: Incident summary from the summarizer.
        activity: Per-participant activity analysis.
        roles: Role and relationship inference results.
        review: Process quality review.
        tactics: List of extracted investigation tactics.
        export_timestamp: Human-readable export timestamp.
        lang: BCP-47 language code for the ``<html lang>`` attribute.
        tz: IANA timezone name for the "Generated" timestamp.

    Returns:
        Self-contained HTML string with no external resource dependencies.
    """
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=True,
    )
    env.filters["at"] = lambda name: name if name.startswith("@") else f"@{name}"
    template = env.get_template("report.html")
    zi = ZoneInfo(tz)
    now_dt = datetime.now(timezone.utc).astimezone(zi)
    tz_label = tz if tz == "UTC" else f"UTC{now_dt.strftime('%z')[:3]}:{now_dt.strftime('%z')[3:]} ({tz})"
    now = now_dt.strftime(f"%Y-%m-%d %H:%M:%S {tz_label}")
    return template.render(
        incident_id=incident_id,
        channel=channel,
        summary=summary,
        activity=activity,
        roles=roles,
        review=review,
        tactics=tactics,
        export_timestamp=export_timestamp,
        lang=lang,
        generated_at=now,
    )
