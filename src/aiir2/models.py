"""Pydantic data models for ai-ir2."""

from __future__ import annotations

import json as _json
from typing import Any, Literal, Optional

from pydantic import AwareDatetime, BaseModel, field_validator, model_validator


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _extract_block_text(blocks: list[dict[str, Any]]) -> list[str]:
    """Recursively extract plain text from Block Kit blocks."""
    texts: list[str] = []
    for block in blocks:
        # Section / header blocks with a direct text object.
        text_obj = block.get("text")
        if isinstance(text_obj, dict):
            t = text_obj.get("text", "")
            if t:
                texts.append(t)
        # Rich-text and other blocks with nested elements.
        for child in block.get("elements", []):
            if isinstance(child, dict):
                t = child.get("text", "")
                if isinstance(t, str) and t:
                    texts.append(t)
                # One more level (rich_text_section → elements).
                for grandchild in child.get("elements", []):
                    if isinstance(grandchild, dict):
                        gt = grandchild.get("text", "")
                        if isinstance(gt, str) and gt:
                            texts.append(gt)
    return texts


# ---------------------------------------------------------------------------
# Input models
# ---------------------------------------------------------------------------


class SlackAttachment(BaseModel):
    """A legacy rich attachment from a Slack message."""

    fallback: str = ""
    color: str = ""
    pretext: str = ""
    title: str = ""
    title_link: str = ""
    text: str = ""
    fields: list[dict[str, Any]] = []
    footer: str = ""
    image_url: str = ""


class SlackMessage(BaseModel):
    """A single message from a scat/stail/scli JSON export."""

    user_id: str
    user_name: str = ""
    post_type: Literal["user", "bot"]
    timestamp: AwareDatetime
    timestamp_unix: str
    text: str
    files: list = []
    attachments: list[SlackAttachment] = []
    blocks: list[dict[str, Any]] = []
    thread_timestamp_unix: str = ""
    is_reply: bool = False

    @model_validator(mode="after")
    def _fill_user_name(self) -> SlackMessage:
        """Fall back to user_id if user_name is empty or missing."""
        if not self.user_name:
            self.user_name = self.user_id
        return self

    @model_validator(mode="after")
    def _fill_text_from_attachments(self) -> SlackMessage:
        """Supplement empty text with content from attachments/blocks.

        When a message's primary content lives in legacy attachments or
        Block Kit blocks, the ``text`` field from the Slack API may be
        empty.  This validator builds a fallback so that downstream
        analysis (defanging, LLM prompts) still sees the content.
        """
        if self.text:
            return self
        parts: list[str] = []
        for att in self.attachments:
            for piece in (att.pretext, att.title, att.text, att.fallback):
                if piece and piece not in parts:
                    parts.append(piece)
        if not parts and self.blocks:
            parts.extend(_extract_block_text(self.blocks))
        if parts:
            self.text = "\n".join(parts)
        return self


class SlackExport(BaseModel):
    """Top-level scat/stail JSON export document."""

    export_timestamp: AwareDatetime
    channel_name: str
    messages: list[SlackMessage]


# ---------------------------------------------------------------------------
# Preprocessed models
# ---------------------------------------------------------------------------


class IoC(BaseModel):
    """An extracted and defanged Indicator of Compromise."""

    original: str
    defanged: str
    type: str  # "ip", "url", "domain", "email", "hash"


class ProcessedMessage(BaseModel):
    """A Slack message after IoC defanging and injection sanitization."""

    user_id: str
    user_name: str
    post_type: str
    timestamp: AwareDatetime
    timestamp_unix: str
    text: str  # defanged and sanitized text, wrapped in nonce-tagged block
    files: list = []
    thread_timestamp_unix: str = ""
    is_reply: bool = False
    iocs: list[IoC] = []
    has_injection_risk: bool = False
    injection_warnings: list[str] = []


class ProcessedExport(BaseModel):
    """A processed export document with security metadata."""

    export_timestamp: AwareDatetime
    channel_name: str
    messages: list[ProcessedMessage]
    security_warnings: list[str] = []
    sanitization_nonce: str = ""
    """Random nonce embedded in <user_message_{nonce}> wrapping tags.

    All messages in this export share the same nonce. LLM system prompts
    must reference this nonce so the model knows which tags delimit user data.
    An empty string indicates the export was produced before nonce support was added;
    callers should generate a fallback nonce in that case.
    """


# ---------------------------------------------------------------------------
# Analysis models
# ---------------------------------------------------------------------------


class TimelineEvent(BaseModel):
    """A single event in the incident timeline."""

    timestamp: str
    actor: str
    event: str


class IncidentSummary(BaseModel):
    """Structured incident summary generated by LLM."""

    title: str
    severity: Optional[str] = None
    affected_systems: list[str] = []
    timeline: list[TimelineEvent] = []
    root_cause: str = ""
    resolution: str = ""
    summary: str = ""

    @field_validator("timeline", mode="before")
    @classmethod
    def parse_timeline_strings(cls, v: object) -> object:
        """Normalize LLM output: parse JSON-string elements into dicts."""
        if not isinstance(v, list):
            return v
        result = []
        for item in v:
            if isinstance(item, str):
                try:
                    parsed = _json.loads(item)
                    result.append(parsed)
                except (_json.JSONDecodeError, ValueError):
                    pass  # skip unparseable strings
            else:
                result.append(item)
        return result


class Action(BaseModel):
    """A single action taken by a participant during the incident."""

    timestamp: str
    purpose: str
    method: str
    findings: str = ""

    @field_validator("purpose", "method", "findings", mode="before")
    @classmethod
    def coerce_list_to_str(cls, v: object) -> str:
        """Normalize LLM output: join lists, convert None to empty string."""
        if v is None:
            return ""
        if isinstance(v, list):
            return "\n".join(str(item) for item in v)
        return v


class ParticipantActivity(BaseModel):
    """Activity summary for a single participant."""

    user_name: str
    role_hint: str
    actions: list[Action] = []


class ActivityAnalysis(BaseModel):
    """Per-participant activity analysis."""

    incident_id: str
    channel: str
    participants: list[ParticipantActivity] = []


class Relationship(BaseModel):
    """A relationship between two participants."""

    from_user: str
    to_user: Optional[str] = None
    relationship_type: str
    description: str

    @field_validator("to_user", mode="before")
    @classmethod
    def coerce_list_to_str(cls, v: object) -> Optional[str]:
        """Join list values (e.g. multiple targets) into a comma-separated string."""
        if isinstance(v, list):
            return ", ".join(str(item) for item in v) if v else None
        return v


class ParticipantRole(BaseModel):
    """Inferred role for a single participant."""

    user_name: str
    inferred_role: str
    confidence: str  # "high", "medium", "low"
    evidence: list[str] = []


class RoleAnalysis(BaseModel):
    """Role and relationship inference results."""

    incident_id: str
    channel: str
    participants: list[ParticipantRole] = []
    relationships: list[Relationship] = []


# ---------------------------------------------------------------------------
# Process review models
# ---------------------------------------------------------------------------


class ResponsePhase(BaseModel):
    """Estimated duration and quality assessment for one IR phase."""

    phase: str  # e.g. "detection", "initial_response", "containment", "resolution"
    estimated_duration: str = ""  # human-readable, e.g. "~15 minutes", "unknown"
    quality: str = "unknown"  # "good" | "adequate" | "poor" | "unknown"
    notes: str = ""


class CommunicationAssessment(BaseModel):
    """Quality of communication and information sharing during the incident."""

    overall: str = ""
    delays_observed: list[str] = []
    silos_observed: list[str] = []


class RoleClarity(BaseModel):
    """Assessment of role clarity and coverage during the incident."""

    ic_identified: bool = False
    ic_name: Optional[str] = None
    gaps: list[str] = []
    overlaps: list[str] = []


class ChecklistItem(BaseModel):
    """A single action item for the next incident."""

    item: str
    priority: str = "medium"  # "high" | "medium" | "low"


class IncidentReview(BaseModel):
    """Structured quality review of an incident response process."""

    incident_id: str = ""
    channel: str = ""
    overall_score: Optional[str] = None  # "excellent"|"good"|"adequate"|"poor"
    phases: list[ResponsePhase] = []
    communication: CommunicationAssessment = CommunicationAssessment()
    role_clarity: RoleClarity = RoleClarity()
    tool_appropriateness: str = ""
    strengths: list[str] = []
    improvements: list[str] = []
    checklist: list[ChecklistItem] = []


# ---------------------------------------------------------------------------
# Knowledge models
# ---------------------------------------------------------------------------


class TacticSource(BaseModel):
    """Source metadata for a tactic knowledge document."""

    channel: str
    participants: list[str] = []


class Tactic(BaseModel):
    """A reusable investigation tactic extracted from an IR conversation."""

    id: str
    title: str
    purpose: str
    category: str  # e.g., "log-analysis", "network-analysis"
    tools: list[str] = []
    procedure: str
    observations: str
    tags: list[str] = []
    confidence: Literal["confirmed", "inferred", "suggested"] = "inferred"
    """Evidence confidence level.

    - ``confirmed``: Command output or explicit result was shared in the channel.
    - ``inferred``: Participant mentioned running/checking something but no output shared.
    - ``suggested``: Proposed as a recommendation; no indication it was executed.
    """
    evidence: str = ""
    """One-sentence rationale explaining the confidence classification."""
    source: TacticSource
    created_at: str  # ISO date string (YYYY-MM-DD)

    @field_validator("procedure", "observations", mode="before")
    @classmethod
    def coerce_list_to_str(cls, v: object) -> str:
        """Join list values returned by some LLMs into a newline-separated string."""
        if isinstance(v, list):
            return "\n".join(str(item) for item in v)
        return v


# ---------------------------------------------------------------------------
# Pipeline models
# ---------------------------------------------------------------------------


class PipelineResult(BaseModel):
    """Result of a full analysis pipeline run."""

    incident_id: str
    output_dir: str
    languages: list[str] = []
    tactic_count: int = 0
    message_count: int = 0
