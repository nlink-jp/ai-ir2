"""Tests for the pipeline orchestrator."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from aiir2.config import GeminiConfig
from aiir2.models import (
    ActivityAnalysis,
    IncidentReview,
    IncidentSummary,
    PipelineResult,
    RoleAnalysis,
    Tactic,
    TacticSource,
)
from aiir2.pipeline import _preprocess, make_incident_id, run_pipeline


# ---------------------------------------------------------------------------
# make_incident_id
# ---------------------------------------------------------------------------


class TestMakeIncidentId:
    """Tests for deterministic incident ID generation."""

    def test_deterministic(self):
        """Same inputs produce the same ID."""
        id1 = make_incident_id("#channel", "2026-03-19T10:00:00+00:00")
        id2 = make_incident_id("#channel", "2026-03-19T10:00:00+00:00")
        assert id1 == id2

    def test_length(self):
        """ID is 12 hex characters."""
        result = make_incident_id("#test", "2026-01-01T00:00:00+00:00")
        assert len(result) == 12
        assert all(c in "0123456789abcdef" for c in result)

    def test_different_inputs(self):
        """Different inputs produce different IDs."""
        id1 = make_incident_id("#ch1", "2026-01-01T00:00:00+00:00")
        id2 = make_incident_id("#ch2", "2026-01-01T00:00:00+00:00")
        assert id1 != id2


# ---------------------------------------------------------------------------
# _preprocess
# ---------------------------------------------------------------------------


class TestPreprocess:
    """Tests for the preprocessing function."""

    def test_preprocess_returns_processed_export(self, sample_export_data):
        """Preprocessing returns a ProcessedExport with correct structure."""
        from aiir2.parser.loader import load_export_from_string
        from aiir2.parser.sanitizer import generate_nonce

        raw = load_export_from_string(json.dumps(sample_export_data))
        nonce = generate_nonce()
        result = _preprocess(raw, nonce)

        assert result.channel_name == "#incident-response"
        assert len(result.messages) == 3
        assert result.sanitization_nonce == nonce

    def test_preprocess_message_fields(self, sample_export_data):
        """Each processed message preserves user metadata."""
        from aiir2.parser.loader import load_export_from_string
        from aiir2.parser.sanitizer import generate_nonce

        raw = load_export_from_string(json.dumps(sample_export_data))
        nonce = generate_nonce()
        result = _preprocess(raw, nonce)

        msg = result.messages[0]
        assert msg.user_name == "alice"
        assert msg.user_id == "U12345ABC"
        assert msg.post_type == "user"
        # Text should be sanitized (wrapped in nonce tags)
        assert nonce in msg.text


# ---------------------------------------------------------------------------
# run_pipeline (fully mocked)
# ---------------------------------------------------------------------------


def _make_mock_summary():
    return IncidentSummary(
        title="Test Incident",
        severity="medium",
        affected_systems=["server-1"],
        timeline=[],
        root_cause="Disk full",
        resolution="Cleared logs",
        summary="A test incident summary.",
    )


def _make_mock_activity():
    return ActivityAnalysis(
        incident_id="test123",
        channel="#test",
        participants=[],
    )


def _make_mock_roles():
    return RoleAnalysis(
        incident_id="test123",
        channel="#test",
        participants=[],
        relationships=[],
    )


def _make_mock_review():
    return IncidentReview(
        incident_id="test123",
        channel="#test",
        overall_score="good",
        phases=[],
        strengths=["Quick response"],
        improvements=["Add runbook"],
        checklist=[],
    )


def _make_mock_tactic():
    return Tactic(
        id="tac-20260319-001",
        title="Check disk usage",
        purpose="Identify disk space issues",
        category="log-analysis",
        tools=["df", "du"],
        procedure="Run df -h to check disk usage.",
        observations="Look for partitions over 90% usage.",
        tags=["disk", "storage"],
        confidence="confirmed",
        evidence="Output was shared in channel.",
        source=TacticSource(channel="#test", participants=["alice"]),
        created_at="2026-03-19",
    )


@pytest.fixture
def mock_config():
    """Return a GeminiConfig that won't hit real APIs."""
    return GeminiConfig(project="test-project", location="us-central1", model="gemini-2.5-flash")


class TestRunPipeline:
    """Tests for the full pipeline orchestration."""

    @patch("aiir2.pipeline.GeminiClient")
    @patch("aiir2.pipeline.translate_report")
    @patch("aiir2.pipeline.extract_tactics")
    @patch("aiir2.pipeline.review_incident")
    @patch("aiir2.pipeline.analyze_roles")
    @patch("aiir2.pipeline.analyze_activity")
    @patch("aiir2.pipeline.summarize_incident")
    def test_output_structure(
        self,
        mock_summarize,
        mock_activity,
        mock_roles,
        mock_review,
        mock_extract,
        mock_translate,
        mock_client_cls,
        sample_export_path,
        tmp_path,
        mock_config,
    ):
        """Pipeline creates the correct output directory structure."""
        mock_summarize.return_value = _make_mock_summary()
        mock_activity.return_value = _make_mock_activity()
        mock_roles.return_value = _make_mock_roles()
        mock_review.return_value = _make_mock_review()
        mock_extract.return_value = [_make_mock_tactic()]
        mock_client_cls.return_value = MagicMock()

        output = tmp_path / "output"
        result = run_pipeline(
            input_path=sample_export_path,
            output_dir=str(output),
            langs=[],
            config=mock_config,
        )

        assert isinstance(result, PipelineResult)
        assert result.output_dir == str(output)
        assert result.message_count == 3
        assert result.tactic_count == 1
        assert "en" in result.languages

        # Check files exist
        assert (output / "en" / "report.md").exists()
        assert (output / "en" / "report.html").exists()
        assert (output / "preprocessed.json").exists()
        assert (output / "knowledge").is_dir()

    @patch("aiir2.pipeline.GeminiClient")
    @patch("aiir2.pipeline.translate_report")
    @patch("aiir2.pipeline.extract_tactics")
    @patch("aiir2.pipeline.review_incident")
    @patch("aiir2.pipeline.analyze_roles")
    @patch("aiir2.pipeline.analyze_activity")
    @patch("aiir2.pipeline.summarize_incident")
    def test_no_tactics(
        self,
        mock_summarize,
        mock_activity,
        mock_roles,
        mock_review,
        mock_extract,
        mock_translate,
        mock_client_cls,
        sample_export_path,
        tmp_path,
        mock_config,
    ):
        """Pipeline handles zero tactics gracefully."""
        mock_summarize.return_value = _make_mock_summary()
        mock_activity.return_value = _make_mock_activity()
        mock_roles.return_value = _make_mock_roles()
        mock_review.return_value = _make_mock_review()
        mock_extract.return_value = []
        mock_client_cls.return_value = MagicMock()

        output = tmp_path / "output"
        result = run_pipeline(
            input_path=sample_export_path,
            output_dir=str(output),
            langs=[],
            config=mock_config,
        )

        assert result.tactic_count == 0
        # Knowledge dir exists but should have no YAML files
        assert (output / "knowledge").is_dir()

    @patch("aiir2.pipeline.GeminiClient")
    @patch("aiir2.pipeline.translate_report")
    @patch("aiir2.pipeline.extract_tactics")
    @patch("aiir2.pipeline.review_incident")
    @patch("aiir2.pipeline.analyze_roles")
    @patch("aiir2.pipeline.analyze_activity")
    @patch("aiir2.pipeline.summarize_incident")
    def test_translation_creates_lang_dirs(
        self,
        mock_summarize,
        mock_activity,
        mock_roles,
        mock_review,
        mock_extract,
        mock_translate,
        mock_client_cls,
        sample_export_path,
        tmp_path,
        mock_config,
    ):
        """Translation creates language-specific directories with reports."""
        mock_summarize.return_value = _make_mock_summary()
        mock_activity.return_value = _make_mock_activity()
        mock_roles.return_value = _make_mock_roles()
        mock_review.return_value = _make_mock_review()
        mock_extract.return_value = [_make_mock_tactic()]
        mock_client_cls.return_value = MagicMock()

        # translate_report returns translated dicts
        mock_translate.return_value = (
            {
                "incident_id": "test123",
                "summary": _make_mock_summary().model_dump(),
                "activity": _make_mock_activity().model_dump(),
                "roles": _make_mock_roles().model_dump(),
                "tactics": [_make_mock_tactic().model_dump()],
            },
            _make_mock_review().model_dump(),
        )

        output = tmp_path / "output"
        result = run_pipeline(
            input_path=sample_export_path,
            output_dir=str(output),
            langs=["ja"],
            config=mock_config,
        )

        assert "ja" in result.languages
        assert (output / "ja" / "report.md").exists()
        assert (output / "ja" / "report.html").exists()

    @patch("aiir2.pipeline.GeminiClient")
    @patch("aiir2.pipeline.translate_report")
    @patch("aiir2.pipeline.extract_tactics")
    @patch("aiir2.pipeline.review_incident")
    @patch("aiir2.pipeline.analyze_roles")
    @patch("aiir2.pipeline.analyze_activity")
    @patch("aiir2.pipeline.summarize_incident")
    def test_auto_output_dir(
        self,
        mock_summarize,
        mock_activity,
        mock_roles,
        mock_review,
        mock_extract,
        mock_translate,
        mock_client_cls,
        sample_export_path,
        tmp_path,
        mock_config,
        monkeypatch,
    ):
        """Empty output_dir uses incident ID as directory name."""
        mock_summarize.return_value = _make_mock_summary()
        mock_activity.return_value = _make_mock_activity()
        mock_roles.return_value = _make_mock_roles()
        mock_review.return_value = _make_mock_review()
        mock_extract.return_value = []
        mock_client_cls.return_value = MagicMock()

        # Change to tmp_path so auto-generated dir is created there
        monkeypatch.chdir(tmp_path)

        result = run_pipeline(
            input_path=sample_export_path,
            output_dir="",
            langs=[],
            config=mock_config,
        )

        # Output dir should be ./{incident_id}
        assert result.incident_id in result.output_dir

    @patch("aiir2.pipeline.GeminiClient")
    @patch("aiir2.pipeline.translate_report")
    @patch("aiir2.pipeline.extract_tactics")
    @patch("aiir2.pipeline.review_incident")
    @patch("aiir2.pipeline.analyze_roles")
    @patch("aiir2.pipeline.analyze_activity")
    @patch("aiir2.pipeline.summarize_incident")
    def test_preprocessed_json_saved(
        self,
        mock_summarize,
        mock_activity,
        mock_roles,
        mock_review,
        mock_extract,
        mock_translate,
        mock_client_cls,
        sample_export_path,
        tmp_path,
        mock_config,
    ):
        """preprocessed.json is saved and contains valid JSON."""
        mock_summarize.return_value = _make_mock_summary()
        mock_activity.return_value = _make_mock_activity()
        mock_roles.return_value = _make_mock_roles()
        mock_review.return_value = _make_mock_review()
        mock_extract.return_value = []
        mock_client_cls.return_value = MagicMock()

        output = tmp_path / "output"
        run_pipeline(
            input_path=sample_export_path,
            output_dir=str(output),
            langs=[],
            config=mock_config,
        )

        preprocessed_path = output / "preprocessed.json"
        assert preprocessed_path.exists()
        data = json.loads(preprocessed_path.read_text())
        assert "messages" in data
        assert "channel_name" in data
        assert len(data["messages"]) == 3
