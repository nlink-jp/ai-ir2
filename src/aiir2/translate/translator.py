"""Translate analysis report and review JSON into a target language."""

from __future__ import annotations

import json
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from aiir2.llm.client import GeminiClient

logger = logging.getLogger(__name__)

# Fields to translate per section (narrative text only).
# Technical identifiers (tool names, commands, IDs, tags, IOCs) are NOT translated.
_TRANSLATE_INSTRUCTIONS = """\
You are a professional technical translator.
Translate the JSON values below into {lang_name}.

Rules:
- Translate ONLY the string values in the JSON.
- Do NOT translate keys, usernames, channel names, or any value that looks like:
  - A shell command or code snippet (e.g., text inside backticks: `grep`, `journalctl -u sshd`)
  - An IP address, domain, URL, file hash, or other indicator of compromise
  - A severity level word: critical, high, medium, low, unknown
  - A confidence word: high, medium, low
  - A relationship type: reports_to, coordinates_with, escalated_to, informed
  - A category slug (kebab-case like log-analysis, linux-auditd)
  - A tactic ID (e.g., tac-20260319-001)
  - An ISO date or timestamp
- Preserve all whitespace and newlines within values.
- Return valid JSON with the exact same structure as the input.
"""

_LANG_NAMES: dict[str, str] = {
    "ja": "Japanese",
    "zh": "Simplified Chinese",
    "ko": "Korean",
    "de": "German",
    "fr": "French",
    "es": "Spanish",
}


SUPPORTED_LANGS = sorted(_LANG_NAMES.keys())


def _lang_name(lang: str) -> str:
    return _LANG_NAMES.get(lang, lang)


def _translate_chunk(data: Any, lang: str, client: GeminiClient) -> Any:
    """Send a JSON chunk to the LLM for translation and return the parsed result."""
    system_prompt = _TRANSLATE_INSTRUCTIONS.format(lang_name=_lang_name(lang))
    user_prompt = json.dumps(data, ensure_ascii=False)
    raw = client.complete_text(system_prompt, user_prompt)
    # Strip markdown code fences if present
    text = raw.strip()
    if text.startswith("```"):
        # Remove opening fence (```json or ```)
        first_newline = text.index("\n")
        text = text[first_newline + 1 :]
        # Remove closing fence
        if text.endswith("```"):
            text = text[: -3].rstrip()
    return json.loads(text)


# ---------------------------------------------------------------------------
# Section-level translators (report)
# ---------------------------------------------------------------------------


def _translate_summary(
    summary: dict[str, Any], lang: str, client: GeminiClient,
) -> dict[str, Any]:
    """Translate narrative fields in the summary section."""
    payload = {
        "title": summary.get("title", ""),
        "root_cause": summary.get("root_cause", ""),
        "resolution": summary.get("resolution", ""),
        "summary": summary.get("summary", ""),
        "timeline": [
            {"timestamp": e["timestamp"], "actor": e["actor"], "event": e["event"]}
            for e in summary.get("timeline", [])
        ],
    }
    translated = _translate_chunk(payload, lang, client)
    result = dict(summary)
    result.update({
        "title": translated.get("title", summary.get("title", "")),
        "root_cause": translated.get("root_cause", summary.get("root_cause", "")),
        "resolution": translated.get("resolution", summary.get("resolution", "")),
        "summary": translated.get("summary", summary.get("summary", "")),
    })
    orig_timeline = summary.get("timeline", [])
    trans_timeline = translated.get("timeline", [])
    merged_timeline = []
    for i, orig_ev in enumerate(orig_timeline):
        ev = dict(orig_ev)
        if i < len(trans_timeline):
            ev["event"] = trans_timeline[i].get("event", orig_ev.get("event", ""))
        merged_timeline.append(ev)
    result["timeline"] = merged_timeline
    return result


def _translate_activity(
    activity: dict[str, Any], lang: str, client: GeminiClient,
) -> dict[str, Any]:
    """Translate narrative fields in the activity section."""
    participants = activity.get("participants", [])
    payload = {
        "participants": [
            {
                "user_name": p["user_name"],
                "role_hint": p.get("role_hint", ""),
                "actions": [
                    {
                        "timestamp": a["timestamp"],
                        "purpose": a.get("purpose", ""),
                        "findings": a.get("findings", ""),
                    }
                    for a in p.get("actions", [])
                ],
            }
            for p in participants
        ],
    }
    translated = _translate_chunk(payload, lang, client)
    result = dict(activity)
    orig_parts = participants
    trans_parts = translated.get("participants", [])
    merged = []
    for i, orig_p in enumerate(orig_parts):
        p = dict(orig_p)
        if i < len(trans_parts):
            tp = trans_parts[i]
            p["role_hint"] = tp.get("role_hint", orig_p.get("role_hint", ""))
            orig_actions = orig_p.get("actions", [])
            trans_actions = tp.get("actions", [])
            merged_actions = []
            for j, orig_a in enumerate(orig_actions):
                a = dict(orig_a)
                if j < len(trans_actions):
                    ta = trans_actions[j]
                    a["purpose"] = ta.get("purpose", orig_a.get("purpose", ""))
                    a["findings"] = ta.get("findings", orig_a.get("findings", ""))
                merged_actions.append(a)
            p["actions"] = merged_actions
        merged.append(p)
    result["participants"] = merged
    return result


def _translate_roles(
    roles: dict[str, Any], lang: str, client: GeminiClient,
) -> dict[str, Any]:
    """Translate narrative fields in the roles section."""
    participants = roles.get("participants", [])
    relationships = roles.get("relationships", [])
    payload = {
        "participants": [
            {
                "user_name": p["user_name"],
                "inferred_role": p.get("inferred_role", ""),
                "evidence": p.get("evidence", []),
            }
            for p in participants
        ],
        "relationships": [
            {
                "from_user": r["from_user"],
                "to_user": r.get("to_user"),
                "description": r.get("description", ""),
            }
            for r in relationships
        ],
    }
    translated = _translate_chunk(payload, lang, client)
    result = dict(roles)
    orig_parts = participants
    trans_parts = translated.get("participants", [])
    merged_parts = []
    for i, orig_p in enumerate(orig_parts):
        p = dict(orig_p)
        if i < len(trans_parts):
            tp = trans_parts[i]
            p["inferred_role"] = tp.get(
                "inferred_role", orig_p.get("inferred_role", ""),
            )
            p["evidence"] = tp.get("evidence", orig_p.get("evidence", []))
        merged_parts.append(p)
    result["participants"] = merged_parts
    orig_rels = relationships
    trans_rels = translated.get("relationships", [])
    merged_rels = []
    for i, orig_r in enumerate(orig_rels):
        r = dict(orig_r)
        if i < len(trans_rels):
            r["description"] = trans_rels[i].get(
                "description", orig_r.get("description", ""),
            )
        merged_rels.append(r)
    result["relationships"] = merged_rels
    return result


def _translate_tactics(
    tactics: list[dict[str, Any]], lang: str, client: GeminiClient,
) -> list[dict[str, Any]]:
    """Translate narrative fields in the tactics list."""
    payload = {
        "tactics": [
            {
                "title": t.get("title", ""),
                "purpose": t.get("purpose", ""),
                "procedure": t.get("procedure", ""),
                "observations": t.get("observations", ""),
                "evidence": t.get("evidence", ""),
            }
            for t in tactics
        ],
    }
    translated = _translate_chunk(payload, lang, client)
    trans_tactics = translated.get("tactics", [])
    result = []
    for i, orig_t in enumerate(tactics):
        t = dict(orig_t)
        if i < len(trans_tactics):
            tt = trans_tactics[i]
            t["title"] = tt.get("title", orig_t.get("title", ""))
            t["purpose"] = tt.get("purpose", orig_t.get("purpose", ""))
            t["procedure"] = tt.get("procedure", orig_t.get("procedure", ""))
            t["observations"] = tt.get("observations", orig_t.get("observations", ""))
            t["evidence"] = tt.get("evidence", orig_t.get("evidence", ""))
        result.append(t)
    return result


# ---------------------------------------------------------------------------
# Section-level translators (review)
# ---------------------------------------------------------------------------


def _translate_review_phases_comms(
    review: dict[str, Any], lang: str, client: GeminiClient,
) -> dict[str, Any]:
    """Translate phases notes and communication/role_clarity narrative fields."""
    phases = review.get("phases", [])
    communication = review.get("communication", {})
    role_clarity = review.get("role_clarity", {})

    payload = {
        "phases": [{"notes": p.get("notes", "")} for p in phases],
        "communication": {
            "overall": communication.get("overall", ""),
            "delays_observed": communication.get("delays_observed", []),
            "silos_observed": communication.get("silos_observed", []),
        },
        "role_clarity": {
            "gaps": role_clarity.get("gaps", []),
            "overlaps": role_clarity.get("overlaps", []),
        },
    }
    translated = _translate_chunk(payload, lang, client)

    # Merge phases notes
    merged_phases = []
    trans_phases = translated.get("phases", [])
    for i, orig_p in enumerate(phases):
        p = dict(orig_p)
        if i < len(trans_phases):
            p["notes"] = trans_phases[i].get("notes", orig_p.get("notes", ""))
        merged_phases.append(p)

    # Merge communication
    trans_comm = translated.get("communication", {})
    merged_comm = dict(communication)
    merged_comm["overall"] = trans_comm.get(
        "overall", communication.get("overall", ""),
    )
    merged_comm["delays_observed"] = trans_comm.get(
        "delays_observed", communication.get("delays_observed", []),
    )
    merged_comm["silos_observed"] = trans_comm.get(
        "silos_observed", communication.get("silos_observed", []),
    )

    # Merge role_clarity text
    trans_rc = translated.get("role_clarity", {})
    merged_rc = dict(role_clarity)
    merged_rc["gaps"] = trans_rc.get("gaps", role_clarity.get("gaps", []))
    merged_rc["overlaps"] = trans_rc.get(
        "overlaps", role_clarity.get("overlaps", []),
    )

    result = dict(review)
    result["phases"] = merged_phases
    result["communication"] = merged_comm
    result["role_clarity"] = merged_rc
    return result


def _translate_review_findings(
    review: dict[str, Any], lang: str, client: GeminiClient,
) -> dict[str, Any]:
    """Translate tool_appropriateness, strengths, improvements, and checklist items."""
    checklist = review.get("checklist", [])
    payload = {
        "tool_appropriateness": review.get("tool_appropriateness", ""),
        "strengths": review.get("strengths", []),
        "improvements": review.get("improvements", []),
        "checklist": [{"item": c.get("item", "")} for c in checklist],
    }
    translated = _translate_chunk(payload, lang, client)

    trans_checklist = translated.get("checklist", [])
    merged_checklist = []
    for i, orig_c in enumerate(checklist):
        c = dict(orig_c)
        if i < len(trans_checklist):
            c["item"] = trans_checklist[i].get("item", orig_c.get("item", ""))
        merged_checklist.append(c)

    result = dict(review)
    result["tool_appropriateness"] = translated.get(
        "tool_appropriateness", review.get("tool_appropriateness", ""),
    )
    result["strengths"] = translated.get(
        "strengths", review.get("strengths", []),
    )
    result["improvements"] = translated.get(
        "improvements", review.get("improvements", []),
    )
    result["checklist"] = merged_checklist
    return result


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def translate_report(
    report: dict[str, Any],
    review: dict[str, Any],
    lang: str,
    client: GeminiClient,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Translate both report and review to target language.

    All translation tasks (report sections + review sections) are executed
    in parallel via ThreadPoolExecutor to minimise wall-clock time.

    Technical fields (tool names, commands, IDs, tags, IOCs) are preserved
    as-is.  Only narrative text is translated.

    Args:
        report: Report dict as produced by the analysis pipeline.
        review: Review dict as produced by the review stage.
        lang: BCP-47 language code (e.g. ``"ja"``, ``"zh"``, ``"de"``).
        client: Configured Gemini client.

    Returns:
        A ``(translated_report, translated_review)`` tuple.  On JSON parse
        failure for any individual section, the original data for that
        section is preserved and a warning is logged.
    """
    translated_report: dict[str, Any] = dict(report)
    translated_report["lang"] = lang

    translated_review: dict[str, Any] = dict(review)
    translated_review["lang"] = lang

    futures: dict[str, Any] = {}
    with ThreadPoolExecutor(max_workers=6) as executor:
        # Report sections
        if report.get("summary"):
            futures["summary"] = executor.submit(
                _safe_translate, _translate_summary,
                report["summary"], lang, client,
            )
        if report.get("activity"):
            futures["activity"] = executor.submit(
                _safe_translate, _translate_activity,
                report["activity"], lang, client,
            )
        if report.get("roles"):
            futures["roles"] = executor.submit(
                _safe_translate, _translate_roles,
                report["roles"], lang, client,
            )
        if report.get("tactics"):
            futures["tactics"] = executor.submit(
                _safe_translate, _translate_tactics,
                report["tactics"], lang, client,
            )
        # Review sections
        futures["review_phases"] = executor.submit(
            _safe_translate, _translate_review_phases_comms,
            translated_review, lang, client,
        )
        futures["review_findings"] = executor.submit(
            _safe_translate, _translate_review_findings,
            translated_review, lang, client,
        )

    # Collect report results
    for key in ("summary", "activity", "roles", "tactics"):
        if key in futures:
            result = futures[key].result()
            if result is not None:
                translated_report[key] = result

    # Collect review results
    review_phases_result = futures["review_phases"].result()
    review_findings_result = futures["review_findings"].result()

    if review_phases_result is not None:
        translated_review["phases"] = review_phases_result.get(
            "phases", translated_review.get("phases", []),
        )
        translated_review["communication"] = review_phases_result.get(
            "communication", translated_review.get("communication", {}),
        )
        translated_review["role_clarity"] = review_phases_result.get(
            "role_clarity", translated_review.get("role_clarity", {}),
        )

    if review_findings_result is not None:
        translated_review["tool_appropriateness"] = review_findings_result.get(
            "tool_appropriateness",
            translated_review.get("tool_appropriateness", ""),
        )
        translated_review["strengths"] = review_findings_result.get(
            "strengths", translated_review.get("strengths", []),
        )
        translated_review["improvements"] = review_findings_result.get(
            "improvements", translated_review.get("improvements", []),
        )
        translated_review["checklist"] = review_findings_result.get(
            "checklist", translated_review.get("checklist", []),
        )

    return translated_report, translated_review


def _safe_translate(fn: Any, *args: Any) -> Any:
    """Call a translation function, returning None on JSON parse error."""
    try:
        return fn(*args)
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        logger.warning("Translation failed for %s, preserving original: %s", fn.__name__, exc)
        return None
