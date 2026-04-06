"""Shared utilities for ai-ir2 modules."""

from __future__ import annotations

from aiir2.models import ProcessedExport


def format_conversation(export: ProcessedExport) -> str:
    """Format conversation messages for LLM input.

    Each message is rendered as ``[YYYY-MM-DD HH:MM:SS] @username: text``.
    Bot messages are prefixed with ``[bot] ``.
    The ``msg.text`` field already contains the nonce-tagged wrapping applied
    during ``aiir2 ingest``.

    Args:
        export: ProcessedExport to format.

    Returns:
        Formatted conversation string.
    """
    lines = []
    for msg in export.messages:
        ts = msg.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        prefix = "[bot] " if msg.post_type == "bot" else ""
        lines.append(f"[{ts}] {prefix}@{msg.user_name}: {msg.text}")
    return "\n".join(lines)
