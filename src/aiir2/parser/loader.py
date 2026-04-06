"""Load and validate scat/stail JSON export files."""

import json
from pathlib import Path

from aiir2.models import SlackExport, SlackMessage


def _load_ndjson(path: Path) -> SlackExport:
    """Load a stail NDJSON export (one JSON object per line).

    Derives channel_name from the file stem and export_timestamp from
    the latest message timestamp.

    Args:
        path: Path to the NDJSON file.

    Returns:
        SlackExport assembled from individual message lines.

    Raises:
        json.JSONDecodeError: If any line is not valid JSON.
        pydantic.ValidationError: If a line does not match SlackMessage schema.
        ValueError: If the file contains no messages.
    """
    messages: list[SlackMessage] = []
    with open(path, encoding="utf-8") as f:
        for line_number, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                messages.append(SlackMessage.model_validate(json.loads(line)))
            except (json.JSONDecodeError, Exception) as e:
                raise ValueError(
                    f"{path}:{line_number}: failed to parse NDJSON line: {e}"
                ) from e
    if not messages:
        raise ValueError(f"No messages found in {path}")
    export_timestamp = max(m.timestamp for m in messages)
    channel_name = path.stem
    return SlackExport(
        export_timestamp=export_timestamp,
        channel_name=channel_name,
        messages=messages,
    )


def load_export(path: Path) -> SlackExport:
    """Load and validate a scat/stail JSON export file.

    Supports two formats:
    - Single JSON object (scat format): ``{"export_timestamp": ..., "channel_name": ..., "messages": [...]}``
    - NDJSON (stail format): one ``SlackMessage`` JSON object per line

    Args:
        path: Path to the JSON export file.

    Returns:
        Validated SlackExport instance.

    Raises:
        FileNotFoundError: If the file does not exist.
        json.JSONDecodeError: If the file is not valid JSON.
        pydantic.ValidationError: If the JSON does not match the expected schema.
        ValueError: If the NDJSON file contains no messages.
    """
    with open(path, encoding="utf-8") as f:
        content = f.read()
    if not content.strip():
        return _load_ndjson(path)  # raises ValueError("No messages found")
    try:
        data = json.loads(content)
        return SlackExport.model_validate(data)
    except json.JSONDecodeError as e:
        if "Extra data" in str(e):
            return _load_ndjson(path)
        raise


def load_export_from_string(content: str) -> SlackExport:
    """Load and validate from a JSON string.

    Args:
        content: JSON string containing the export data.

    Returns:
        Validated SlackExport instance.

    Raises:
        json.JSONDecodeError: If the content is not valid JSON.
        pydantic.ValidationError: If the JSON does not match the expected schema.
    """
    data = json.loads(content)
    return SlackExport.model_validate(data)
