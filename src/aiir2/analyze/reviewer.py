"""Incident response process quality reviewer using Gemini structured output."""

from __future__ import annotations

import json

from aiir2.llm.client import GeminiClient
from aiir2.models import IncidentReview


def _build_system_prompt() -> str:
    """Build the system prompt for IR process review.

    Unlike the other analysis modules, this prompt does not require a nonce
    because user-sourced message text is not passed to the LLM -- only the
    already-structured report data (summary, activity, roles, tactics) is used.

    Returns:
        System prompt string.
    """
    return """You are an expert incident response process evaluator.
Analyze the provided structured incident report and evaluate the quality of how the team responded.

IMPORTANT: Always respond in English regardless of the language of the input.

Focus on the PROCESS (how the team worked), not the technical content of the incident itself.
Assess these dimensions:
- Phase timing: estimate how long each IR phase took and whether the pace was appropriate
- Communication quality: information sharing, delays, silos, escalation timeliness
- Role clarity: whether roles were well-defined, IC presence, gaps or overlaps
- Tool appropriateness: whether the right tools and methods were used.
  Each tactic in the report carries a "confidence" field -- use it as follows:
    * "confirmed": tool output or explicit results were shared in the channel.
      Treat these as tools that were definitely used; evaluate their appropriateness.
    * "inferred": a participant mentioned using the tool but shared no output.
      Note these as likely used but acknowledge the lack of direct evidence.
    * "suggested": proposed as a recommendation only; do NOT treat as having been used.
  Base your overall tool_appropriateness assessment only on "confirmed" tactics.
  If the only evidence for a tool is "inferred" or "suggested", say so explicitly.
- Strengths: concrete things the team did well
- Improvements: specific, actionable suggestions for next time
- Next-incident checklist: prioritised preparation items"""


def _format_report_for_review(report: dict) -> str:
    """Serialize the structured sections of a report dict for LLM input.

    Deliberately excludes raw message text to avoid re-exposing user data
    and to minimise token consumption. Only the already-analysed fields
    (summary, activity, roles, tactics) are included.

    Args:
        report: Report dict as produced by the pipeline.

    Returns:
        Compact JSON string suitable for inclusion in the LLM prompt.
    """
    payload = {
        "channel": report.get("metadata", {}).get("channel", report.get("channel", "")),
        "incident_id": report.get("incident_id", ""),
        "summary": report.get("summary", {}),
        "activity": report.get("activity", {}),
        "roles": report.get("roles", {}),
        "tactics": report.get("tactics", []),
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def review_incident(report_data: dict, client: GeminiClient) -> IncidentReview:
    """Generate a process quality review from a completed incident report.

    Args:
        report_data: Report dict as produced by the pipeline.
        client: Configured Gemini client.

    Returns:
        Structured IncidentReview model.
    """
    system_prompt = _build_system_prompt()
    channel = report_data.get("metadata", {}).get(
        "channel", report_data.get("channel", "")
    )
    report_text = _format_report_for_review(report_data)

    user_prompt = f"""Evaluate the incident response process quality for channel {channel}:

{report_text}

Provide a structured process quality review."""

    result = client.complete_structured(system_prompt, user_prompt, IncidentReview)

    # Fill in fields the LLM may have omitted
    if not result.incident_id:
        result.incident_id = report_data.get("incident_id", "")
    if not result.channel:
        result.channel = channel

    return result
