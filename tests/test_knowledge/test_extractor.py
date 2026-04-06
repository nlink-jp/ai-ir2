"""Tests for aiir2.knowledge.extractor module."""

from __future__ import annotations

from datetime import date
from unittest.mock import MagicMock

import pytest

from aiir2.knowledge.extractor import (
    _RawTactic,
    _TacticsResponse,
    _build_system_prompt,
    _generate_tactic_id,
    _get_participants,
    extract_tactics,
)
from aiir2.models import ProcessedExport, ProcessedMessage


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_export(**kwargs) -> ProcessedExport:
    """Create a minimal ProcessedExport for testing."""
    defaults = dict(
        export_timestamp="2026-03-19T10:00:00Z",
        channel_name="#incident-response",
        messages=[
            ProcessedMessage(
                user_id="U001",
                user_name="alice",
                post_type="user",
                timestamp="2026-03-19T09:55:00Z",
                timestamp_unix="1742378100.000000",
                text="Server is down, checking logs.",
            ),
            ProcessedMessage(
                user_id="U002",
                user_name="bob",
                post_type="user",
                timestamp="2026-03-19T09:56:00Z",
                timestamp_unix="1742378160.000000",
                text="Running kubectl get pods -n production",
            ),
            ProcessedMessage(
                user_id="B001",
                user_name="alertbot",
                post_type="bot",
                timestamp="2026-03-19T09:57:00Z",
                timestamp_unix="1742378220.000000",
                text="Alert resolved.",
            ),
        ],
        sanitization_nonce="abc123",
    )
    defaults.update(kwargs)
    return ProcessedExport(**defaults)


def _make_mock_client(raw_tactics: list[dict] | None = None) -> MagicMock:
    """Create a mock GeminiClient that returns a _TacticsResponse."""
    if raw_tactics is None:
        raw_tactics = [
            {
                "title": "Check Pod Logs",
                "purpose": "Identify failing pods",
                "category": "container-analysis",
                "tools": ["kubectl"],
                "procedure": "1. Run kubectl get pods\n2. Check logs",
                "observations": "CrashLoopBackOff indicates restart loops",
                "tags": ["kubernetes", "pods"],
                "confidence": "confirmed",
                "evidence": "bob pasted kubectl output at 09:56",
            },
        ]
    response = _TacticsResponse(
        tactics=[_RawTactic(**t) for t in raw_tactics]
    )
    client = MagicMock()
    client.complete_structured.return_value = response
    return client


# ---------------------------------------------------------------------------
# _generate_tactic_id
# ---------------------------------------------------------------------------


class TestGenerateTacticId:
    def test_format(self):
        result = _generate_tactic_id(date(2026, 3, 19), 1)
        assert result == "tac-20260319-001"

    def test_sequence_padding(self):
        result = _generate_tactic_id(date(2026, 3, 19), 42)
        assert result == "tac-20260319-042"

    def test_three_digit_sequence(self):
        result = _generate_tactic_id(date(2026, 1, 1), 100)
        assert result == "tac-20260101-100"


# ---------------------------------------------------------------------------
# _get_participants
# ---------------------------------------------------------------------------


class TestGetParticipants:
    def test_excludes_bots(self):
        export = _make_export()
        participants = _get_participants(export)
        assert "alertbot" not in participants

    def test_returns_user_names(self):
        export = _make_export()
        participants = _get_participants(export)
        assert participants == ["alice", "bob"]

    def test_deduplicates(self):
        export = _make_export(
            messages=[
                ProcessedMessage(
                    user_id="U001",
                    user_name="alice",
                    post_type="user",
                    timestamp="2026-03-19T09:55:00Z",
                    timestamp_unix="1742378100.000000",
                    text="First message",
                ),
                ProcessedMessage(
                    user_id="U001",
                    user_name="alice",
                    post_type="user",
                    timestamp="2026-03-19T09:56:00Z",
                    timestamp_unix="1742378160.000000",
                    text="Second message",
                ),
            ]
        )
        participants = _get_participants(export)
        assert participants == ["alice"]

    def test_empty_messages(self):
        export = _make_export(messages=[])
        participants = _get_participants(export)
        assert participants == []


# ---------------------------------------------------------------------------
# _build_system_prompt
# ---------------------------------------------------------------------------


class TestBuildSystemPrompt:
    def test_contains_nonce(self):
        prompt = _build_system_prompt("testnonce123")
        assert "user_message_testnonce123" in prompt

    def test_contains_categories(self):
        prompt = _build_system_prompt("nonce")
        assert "log-analysis" in prompt
        assert "container-analysis" in prompt
        assert "windows-event-log" in prompt
        assert "macos-unified-logging" in prompt
        assert "linux-systemd" in prompt

    def test_contains_confidence_levels(self):
        prompt = _build_system_prompt("nonce")
        assert "confirmed" in prompt
        assert "inferred" in prompt
        assert "suggested" in prompt

    def test_contains_ioc_safety(self):
        prompt = _build_system_prompt("nonce")
        assert "hxxp://" in prompt
        assert "defang" in prompt.lower()


# ---------------------------------------------------------------------------
# extract_tactics
# ---------------------------------------------------------------------------


class TestExtractTactics:
    def test_returns_tactics(self):
        export = _make_export()
        client = _make_mock_client()
        tactics = extract_tactics(export, client)
        assert len(tactics) == 1

    def test_tactic_id_generated(self):
        export = _make_export()
        client = _make_mock_client()
        tactics = extract_tactics(export, client)
        assert tactics[0].id == "tac-20260319-001"

    def test_tactic_fields_populated(self):
        export = _make_export()
        client = _make_mock_client()
        tactics = extract_tactics(export, client)
        t = tactics[0]
        assert t.title == "Check Pod Logs"
        assert t.purpose == "Identify failing pods"
        assert t.category == "container-analysis"
        assert t.tools == ["kubectl"]
        assert t.confidence == "confirmed"
        assert t.evidence == "bob pasted kubectl output at 09:56"

    def test_source_metadata(self):
        export = _make_export()
        client = _make_mock_client()
        tactics = extract_tactics(export, client)
        assert tactics[0].source.channel == "#incident-response"
        assert tactics[0].source.participants == ["alice", "bob"]

    def test_created_at(self):
        export = _make_export()
        client = _make_mock_client()
        tactics = extract_tactics(export, client)
        assert tactics[0].created_at == "2026-03-19"

    def test_multiple_tactics_sequential_ids(self):
        raw_tactics = [
            {
                "title": f"Tactic {i}",
                "purpose": f"Purpose {i}",
                "category": "log-analysis",
                "procedure": "step 1",
                "observations": "obs",
            }
            for i in range(1, 4)
        ]
        export = _make_export()
        client = _make_mock_client(raw_tactics)
        tactics = extract_tactics(export, client)
        assert len(tactics) == 3
        assert tactics[0].id == "tac-20260319-001"
        assert tactics[1].id == "tac-20260319-002"
        assert tactics[2].id == "tac-20260319-003"

    def test_invalid_confidence_defaults_to_inferred(self):
        raw_tactics = [
            {
                "title": "Tactic",
                "purpose": "Purpose",
                "category": "other",
                "procedure": "step",
                "observations": "obs",
                "confidence": "maybe",
            }
        ]
        export = _make_export()
        client = _make_mock_client(raw_tactics)
        tactics = extract_tactics(export, client)
        assert tactics[0].confidence == "inferred"

    def test_empty_tactics_response(self):
        export = _make_export()
        client = _make_mock_client([])
        tactics = extract_tactics(export, client)
        assert tactics == []

    def test_calls_complete_structured_with_tactics_response(self):
        export = _make_export()
        client = _make_mock_client()
        extract_tactics(export, client)
        client.complete_structured.assert_called_once()
        _, _, schema = client.complete_structured.call_args[0]
        assert schema is _TacticsResponse

    def test_fallback_nonce_when_empty(self):
        """When sanitization_nonce is empty, a fallback nonce is generated."""
        export = _make_export(sanitization_nonce="")
        client = _make_mock_client()
        extract_tactics(export, client)
        call_args = client.complete_structured.call_args[0]
        system_prompt = call_args[0]
        # Should contain user_message_ with some hex nonce (not empty)
        assert "user_message_" in system_prompt
        # Should NOT contain user_message_ followed by > (empty nonce)
        assert "user_message_>" not in system_prompt
