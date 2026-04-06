"""Tests for aiir2.parser.loader module."""

import json
import textwrap

import pytest

from aiir2.parser.loader import load_export, load_export_from_string


def test_load_export(sample_export_path):
    """Test loading a valid export from a file path."""
    export = load_export(sample_export_path)
    assert export.channel_name == "#incident-response"
    assert len(export.messages) == 3


def test_load_export_message_fields(sample_export_path):
    """Test that message fields are correctly loaded."""
    export = load_export(sample_export_path)
    first = export.messages[0]
    assert first.user_id == "U12345ABC"
    assert first.user_name == "alice"
    assert first.post_type == "user"
    assert "192.168.1.100" in first.text
    assert first.is_reply is False
    assert first.thread_timestamp_unix == ""


def test_load_export_from_string(sample_export_data):
    """Test loading from a JSON string."""
    export = load_export_from_string(json.dumps(sample_export_data))
    assert len(export.messages) == 3
    assert export.channel_name == "#incident-response"


def test_load_export_timestamp_parsed(sample_export_data):
    """Test that timestamps are parsed as datetime objects."""
    from datetime import datetime, timezone

    export = load_export_from_string(json.dumps(sample_export_data))
    assert isinstance(export.export_timestamp, datetime)
    assert export.messages[0].timestamp.year == 2026


def test_load_invalid_raises():
    """Test that loading invalid data raises an exception."""
    with pytest.raises(Exception):
        load_export_from_string('{"invalid": "data"}')


def test_load_missing_required_field_raises():
    """Test that missing required fields raise ValidationError."""
    import json

    from pydantic import ValidationError

    # Missing 'messages' field
    data = {"export_timestamp": "2026-03-19T10:00:00Z", "channel_name": "#test"}
    with pytest.raises(ValidationError):
        load_export_from_string(json.dumps(data))


def test_load_invalid_post_type_raises():
    """Test that an invalid post_type raises ValidationError."""
    import json

    from pydantic import ValidationError

    data = {
        "export_timestamp": "2026-03-19T10:00:00Z",
        "channel_name": "#test",
        "messages": [
            {
                "user_id": "U123",
                "user_name": "alice",
                "post_type": "invalid_type",  # must be "user" or "bot"
                "timestamp": "2026-03-19T09:55:00Z",
                "timestamp_unix": "1742378100.000000",
                "text": "hello",
                "files": [],
                "thread_timestamp_unix": "",
                "is_reply": False,
            }
        ],
    }
    with pytest.raises(ValidationError):
        load_export_from_string(json.dumps(data))


# ---------------------------------------------------------------------------
# NDJSON (stail format) tests
# ---------------------------------------------------------------------------

_NDJSON_LINE1 = {
    "user_id": "U111",
    "user_name": "alice",
    "post_type": "user",
    "timestamp": "2026-03-19T09:00:00Z",
    "timestamp_unix": "1742378000.000000",
    "text": "suspicious login detected",
    "files": [],
    "is_reply": False,
}
_NDJSON_LINE2 = {
    "user_id": "U222",
    "user_name": "bob",
    "post_type": "user",
    "timestamp": "2026-03-19T09:05:00Z",
    "timestamp_unix": "1742378300.000000",
    "text": "investigating now",
    "files": [],
    "is_reply": False,
}


@pytest.fixture()
def ndjson_file(tmp_path):
    """Write a 2-message NDJSON file and return the path."""
    p = tmp_path / "incident_channel.json"
    p.write_text(
        json.dumps(_NDJSON_LINE1) + "\n" + json.dumps(_NDJSON_LINE2) + "\n",
        encoding="utf-8",
    )
    return p


def test_load_ndjson_message_count(ndjson_file):
    """NDJSON export loads all message lines."""
    export = load_export(ndjson_file)
    assert len(export.messages) == 2


def test_load_ndjson_channel_name_from_stem(ndjson_file):
    """channel_name is derived from the file stem."""
    export = load_export(ndjson_file)
    assert export.channel_name == "incident_channel"


def test_load_ndjson_export_timestamp_is_latest(ndjson_file):
    """export_timestamp equals the latest message timestamp."""
    export = load_export(ndjson_file)
    assert export.export_timestamp == export.messages[-1].timestamp


def test_load_ndjson_message_fields(ndjson_file):
    """Message fields are correctly parsed from NDJSON lines."""
    export = load_export(ndjson_file)
    assert export.messages[0].user_name == "alice"
    assert export.messages[1].text == "investigating now"


def test_load_ndjson_blank_lines_ignored(tmp_path):
    """Blank lines in NDJSON are silently ignored."""
    p = tmp_path / "ch.json"
    p.write_text(
        "\n" + json.dumps(_NDJSON_LINE1) + "\n\n" + json.dumps(_NDJSON_LINE2) + "\n",
        encoding="utf-8",
    )
    export = load_export(p)
    assert len(export.messages) == 2


def test_load_ndjson_empty_file_raises(tmp_path):
    """Empty NDJSON file raises ValueError."""
    p = tmp_path / "empty.json"
    p.write_text("", encoding="utf-8")
    with pytest.raises(ValueError, match="No messages found"):
        load_export(p)


def test_missing_user_name_falls_back_to_user_id():
    """Messages without user_name should use user_id as fallback."""
    data = {
        "export_timestamp": "2026-03-19T10:00:00Z",
        "channel_name": "#test",
        "messages": [
            {
                "user_id": "W01790AAGGM",
                "post_type": "user",
                "timestamp": "2026-03-19T09:00:00Z",
                "timestamp_unix": "1742378000.000000",
                "text": "message from deactivated user",
                "files": [],
                "is_reply": False,
            },
            {
                "user_id": "U999",
                "user_name": "",
                "post_type": "bot",
                "timestamp": "2026-03-19T09:01:00Z",
                "timestamp_unix": "1742378060.000000",
                "text": "bot with empty name",
                "files": [],
                "is_reply": False,
            },
        ],
    }
    export = load_export_from_string(json.dumps(data))
    assert len(export.messages) == 2
    # Missing user_name → falls back to user_id
    assert export.messages[0].user_name == "W01790AAGGM"
    # Empty user_name → also falls back to user_id
    assert export.messages[1].user_name == "U999"


# ---------------------------------------------------------------------------
# Attachments and blocks
# ---------------------------------------------------------------------------


def test_attachment_fields_parsed():
    """Attachment objects are parsed and available on SlackMessage."""
    data = {
        "export_timestamp": "2026-03-19T10:00:00Z",
        "channel_name": "#test",
        "messages": [
            {
                "user_id": "B001",
                "user_name": "alert-bot",
                "post_type": "bot",
                "timestamp": "2026-03-19T09:55:00Z",
                "timestamp_unix": "1742378100.000000",
                "text": "fallback text",
                "files": [],
                "attachments": [
                    {
                        "fallback": "Server is down",
                        "color": "#ff0000",
                        "title": "Alert",
                        "text": "Production server unreachable",
                        "fields": [{"title": "Severity", "value": "Critical", "short": True}],
                    }
                ],
                "is_reply": False,
            }
        ],
    }
    export = load_export_from_string(json.dumps(data))
    msg = export.messages[0]
    assert len(msg.attachments) == 1
    att = msg.attachments[0]
    assert att.fallback == "Server is down"
    assert att.color == "#ff0000"
    assert att.title == "Alert"
    assert att.text == "Production server unreachable"
    assert len(att.fields) == 1
    # text is not empty, so attachments don't override it
    assert msg.text == "fallback text"


def test_attachment_text_fallback_when_text_empty():
    """When text is empty, attachment content is used as fallback."""
    data = {
        "export_timestamp": "2026-03-19T10:00:00Z",
        "channel_name": "#test",
        "messages": [
            {
                "user_id": "B001",
                "post_type": "bot",
                "timestamp": "2026-03-19T09:55:00Z",
                "timestamp_unix": "1742378100.000000",
                "text": "",
                "files": [],
                "attachments": [
                    {
                        "title": "CPU Alert",
                        "text": "Server cpu-1 at 95%",
                        "fallback": "CPU > 90%",
                    }
                ],
                "is_reply": False,
            }
        ],
    }
    export = load_export_from_string(json.dumps(data))
    msg = export.messages[0]
    assert "CPU Alert" in msg.text
    assert "Server cpu-1 at 95%" in msg.text


def test_blocks_fields_parsed():
    """Block Kit JSON is parsed and available on SlackMessage."""
    data = {
        "export_timestamp": "2026-03-19T10:00:00Z",
        "channel_name": "#test",
        "messages": [
            {
                "user_id": "B001",
                "post_type": "bot",
                "timestamp": "2026-03-19T09:55:00Z",
                "timestamp_unix": "1742378100.000000",
                "text": "Hello world",
                "files": [],
                "blocks": [
                    {"type": "section", "text": {"type": "mrkdwn", "text": "Hello *world*"}}
                ],
                "is_reply": False,
            }
        ],
    }
    export = load_export_from_string(json.dumps(data))
    msg = export.messages[0]
    assert len(msg.blocks) == 1
    assert msg.blocks[0]["type"] == "section"
    # text is not empty, so blocks don't override it
    assert msg.text == "Hello world"


def test_blocks_text_fallback_when_text_empty():
    """When text is empty and no attachments, block text is used as fallback."""
    data = {
        "export_timestamp": "2026-03-19T10:00:00Z",
        "channel_name": "#test",
        "messages": [
            {
                "user_id": "B001",
                "post_type": "bot",
                "timestamp": "2026-03-19T09:55:00Z",
                "timestamp_unix": "1742378100.000000",
                "text": "",
                "files": [],
                "blocks": [
                    {"type": "section", "text": {"type": "mrkdwn", "text": "Important *alert*"}}
                ],
                "is_reply": False,
            }
        ],
    }
    export = load_export_from_string(json.dumps(data))
    msg = export.messages[0]
    assert "Important *alert*" in msg.text


def test_extra_fields_ignored():
    """Unknown fields in export JSON are silently ignored (Pydantic default)."""
    data = {
        "export_timestamp": "2026-03-19T10:00:00Z",
        "channel_name": "#test",
        "messages": [
            {
                "user_id": "U001",
                "post_type": "user",
                "timestamp": "2026-03-19T09:55:00Z",
                "timestamp_unix": "1742378100.000000",
                "text": "hi",
                "files": [],
                "some_future_field": "should be ignored",
                "is_reply": False,
            }
        ],
    }
    export = load_export_from_string(json.dumps(data))
    assert len(export.messages) == 1
    assert export.messages[0].text == "hi"
