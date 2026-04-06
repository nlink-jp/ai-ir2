"""Tests for aiir2.translate.translator module."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from aiir2.translate.translator import (
    SUPPORTED_LANGS,
    _LANG_NAMES,
    translate_report,
)


def _make_mock_client(response_map: dict[str, str] | None = None):
    """Create a mock GeminiClient that returns translated JSON text.

    If *response_map* is None, the mock translates by prefixing string
    values with ``[JA]`` (a cheap deterministic fake).
    """
    client = MagicMock()

    def _complete_text(system_prompt: str, user_prompt: str) -> str:
        if response_map is not None:
            # Return canned response keyed by a substring of the user prompt
            for key, value in response_map.items():
                if key in user_prompt:
                    return value
            return user_prompt  # fallback: echo

        # Default behaviour: prefix every string value with [JA]
        data = json.loads(user_prompt)
        translated = _prefix_strings(data)
        return json.dumps(translated, ensure_ascii=False)

    client.complete_text.side_effect = _complete_text
    return client


def _prefix_strings(obj):
    """Recursively prefix string values with [JA]."""
    if isinstance(obj, str):
        return f"[JA]{obj}" if obj else ""
    if isinstance(obj, list):
        return [_prefix_strings(item) for item in obj]
    if isinstance(obj, dict):
        return {k: _prefix_strings(v) for k, v in obj.items()}
    return obj


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def sample_report() -> dict:
    return {
        "summary": {
            "title": "SSH Brute Force Incident",
            "severity": "high",
            "root_cause": "Weak password on admin account",
            "resolution": "Password rotated and MFA enabled",
            "summary": "Attacker brute-forced SSH on 192.168.1[.]10",
            "timeline": [
                {
                    "timestamp": "2026-03-19T10:00:00Z",
                    "actor": "alice",
                    "event": "Detected anomalous login attempts",
                },
            ],
        },
        "activity": {
            "participants": [
                {
                    "user_name": "alice",
                    "role_hint": "Lead analyst",
                    "actions": [
                        {
                            "timestamp": "2026-03-19T10:05:00Z",
                            "tool": "journalctl",
                            "command": "journalctl -u sshd --since '2026-03-19'",
                            "purpose": "Check SSH login attempts",
                            "findings": "Found 5000 failed logins from 10.0.0[.]5",
                        },
                    ],
                },
            ],
        },
        "roles": {
            "participants": [
                {
                    "user_name": "alice",
                    "inferred_role": "Incident Commander",
                    "evidence": ["Coordinated response", "Made key decisions"],
                },
            ],
            "relationships": [
                {
                    "from_user": "alice",
                    "to_user": "bob",
                    "type": "reports_to",
                    "description": "Alice reports to Bob",
                },
            ],
        },
        "tactics": [
            {
                "id": "tac-20260319-001",
                "title": "SSH Log Analysis",
                "category": "log-analysis",
                "purpose": "Identify brute force patterns",
                "procedure": "Run journalctl -u sshd and grep for Failed",
                "observations": "Look for repeated IPs",
                "evidence": "5000 failed attempts from single IP",
                "tools": ["journalctl", "grep"],
            },
        ],
    }


@pytest.fixture()
def sample_review() -> dict:
    return {
        "incident_id": "INC-2026-001",
        "overall_score": 8,
        "phases": [
            {
                "name": "Detection",
                "quality_score": 9,
                "notes": "Quick detection via automated alerts",
            },
        ],
        "communication": {
            "overall": "Good cross-team communication",
            "delays_observed": ["Slight delay in notifying management"],
            "silos_observed": [],
        },
        "role_clarity": {
            "gaps": ["No backup IC assigned"],
            "overlaps": [],
        },
        "tool_appropriateness": "Tools were well-suited for the investigation",
        "strengths": ["Fast containment", "Good documentation"],
        "improvements": ["Add automated blocking rules"],
        "checklist": [
            {"item": "Containment completed", "priority": "high", "done": True},
            {"item": "Evidence preserved", "priority": "medium", "done": True},
        ],
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestTranslateReportPreservesTechnicalFields:
    """Verify that technical fields (tool names, IPs, IDs) are preserved."""

    def test_translate_report_preserves_technical_fields(
        self, sample_report, sample_review,
    ):
        client = _make_mock_client()
        t_report, t_review = translate_report(
            sample_report, sample_review, "ja", client,
        )

        # Report: severity is not in the translation payload, stays unchanged
        assert t_report["summary"]["severity"] == "high"

        # Report: timeline timestamps and actors are preserved
        ev = t_report["summary"]["timeline"][0]
        assert ev["timestamp"] == "2026-03-19T10:00:00Z"
        assert ev["actor"] == "alice"

        # Report: tool and command in activity are preserved (not in payload)
        action = t_report["activity"]["participants"][0]["actions"][0]
        assert action["tool"] == "journalctl"
        assert action["command"] == "journalctl -u sshd --since '2026-03-19'"

        # Report: tactic ID, category, tools are preserved
        tactic = t_report["tactics"][0]
        assert tactic["id"] == "tac-20260319-001"
        assert tactic["category"] == "log-analysis"
        assert tactic["tools"] == ["journalctl", "grep"]

        # Review: incident_id and scores are preserved
        assert t_review["incident_id"] == "INC-2026-001"
        assert t_review["overall_score"] == 8
        assert t_review["phases"][0]["name"] == "Detection"
        assert t_review["phases"][0]["quality_score"] == 9
        assert t_review["checklist"][0]["priority"] == "high"
        assert t_review["checklist"][0]["done"] is True


class TestTranslateReportReturnsTuple:
    """Verify that translate_report returns both report and review dicts."""

    def test_translate_report_returns_translated_tuple(
        self, sample_report, sample_review,
    ):
        client = _make_mock_client()
        t_report, t_review = translate_report(
            sample_report, sample_review, "ja", client,
        )

        # Both should be dicts
        assert isinstance(t_report, dict)
        assert isinstance(t_review, dict)

        # Both should have lang set
        assert t_report["lang"] == "ja"
        assert t_review["lang"] == "ja"

        # Report narrative fields should be translated (prefixed with [JA])
        assert t_report["summary"]["title"].startswith("[JA]")
        assert t_report["summary"]["root_cause"].startswith("[JA]")
        assert t_report["activity"]["participants"][0]["role_hint"].startswith("[JA]")
        assert t_report["roles"]["participants"][0]["inferred_role"].startswith("[JA]")
        assert t_report["tactics"][0]["title"].startswith("[JA]")

        # Review narrative fields should be translated
        assert t_review["phases"][0]["notes"].startswith("[JA]")
        assert t_review["communication"]["overall"].startswith("[JA]")
        assert t_review["tool_appropriateness"].startswith("[JA]")
        assert t_review["strengths"][0].startswith("[JA]")
        assert t_review["checklist"][0]["item"].startswith("[JA]")


class TestTranslateReportFallbackOnJsonError:
    """Verify that invalid JSON from LLM preserves the original data."""

    def test_translate_report_fallback_on_json_error(
        self, sample_report, sample_review,
    ):
        # Return invalid JSON for all requests
        client = MagicMock()
        client.complete_text.return_value = "NOT VALID JSON {{{{"

        t_report, t_review = translate_report(
            sample_report, sample_review, "ja", client,
        )

        # Original data should be preserved on failure
        assert t_report["summary"]["title"] == "SSH Brute Force Incident"
        assert t_report["summary"]["root_cause"] == "Weak password on admin account"
        assert t_review["phases"][0]["notes"] == "Quick detection via automated alerts"
        assert t_review["tool_appropriateness"] == "Tools were well-suited for the investigation"

        # lang should still be set
        assert t_report["lang"] == "ja"
        assert t_review["lang"] == "ja"


class TestSupportedLanguages:
    """Verify LANG_NAMES contains expected languages."""

    def test_supported_languages(self):
        expected = {"ja", "zh", "ko", "de", "fr", "es"}
        assert expected == set(_LANG_NAMES.keys())
        assert SUPPORTED_LANGS == sorted(expected)
