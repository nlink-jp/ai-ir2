"""Prompt injection detection and sanitization for LLM inputs.

Detects potential prompt injection attempts in user-sourced text and wraps
the text in safety tags to signal to the LLM that it is data, not instructions.

## Nonce-tagged wrapping strategy

A naive approach wraps text in a fixed tag such as ``<user_message>``.
This is exploitable: an attacker who knows the tag name can embed
``</user_message>`` in their Slack message to close the data block early,
then inject instructions outside it.

To counter this, ``sanitize_for_llm()`` generates a cryptographically random
nonce per preprocessing session and embeds it in the tag name:

    <user_message_3a7f2c1d>
    ...attacker text...
    </user_message_3a7f2c1d>

The nonce is unknown at the time the attacker writes the message, so they
cannot predict the closing tag. The same nonce must be referenced in the
LLM system prompt so the model knows which tags delimit user data.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Injection detection patterns
# ---------------------------------------------------------------------------

# Each pattern is a tuple of (pattern_string, description)
_INJECTION_PATTERNS: list[tuple[str, str]] = [
    (r"ignore\s+(?:(?:previous|all|above|prior)\s+)*instructions?", "Instruction override attempt"),
    (r"forget\s+(everything|all|previous|prior)", "Memory wipe attempt"),
    (r"you\s+are\s+now\s+", "Persona reassignment attempt"),
    (r"new\s+instructions?\s*:", "New instruction injection"),
    (r"system\s*:\s*", "System prompt injection marker"),
    (r"<\s*/?system\s*>", "XML system tag injection"),
    (r"<\s*/?instructions?\s*>", "XML instructions tag injection"),
    (r"\[INST\]", "Llama instruction marker"),
    (r"###\s*instruction", "Markdown instruction header injection"),
    (r"act\s+as\s+", "Role-play directive"),
    (r"roleplay\s+as", "Role-play directive"),
    (r"pretend\s+(you\s+are|to\s+be)", "Persona pretend directive"),
    (r"disregard\s+(previous|all|above|prior)", "Instruction disregard attempt"),
    (
        r"override\s+(previous|system|all)\s+(prompt|instructions?)?",
        "System override attempt",
    ),
]

# Compiled patterns for efficiency
_COMPILED_PATTERNS = [
    (re.compile(pattern, re.IGNORECASE), description)
    for pattern, description in _INJECTION_PATTERNS
]


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass
class SanitizationResult:
    """Result of sanitizing text for LLM input.

    Attributes:
        text: The sanitized text, wrapped in a nonce-tagged block.
        nonce: The random nonce embedded in the wrapping tag name.
            Must be passed to the LLM system prompt so it knows which
            tag delimits user data.
        has_risk: Whether any injection patterns were detected.
        warnings: Descriptions of detected injection patterns.
    """

    text: str
    nonce: str
    has_risk: bool
    warnings: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Public functions
# ---------------------------------------------------------------------------


def generate_nonce() -> str:
    """Generate a cryptographically random nonce for tag name injection defense.

    Returns:
        16-character lowercase hex string (64 bits of entropy).
    """
    return secrets.token_hex(8)


def detect_injection(text: str) -> list[str]:
    """Detect potential prompt injection patterns in text.

    Args:
        text: Text to scan for injection patterns.

    Returns:
        List of warning strings describing detected patterns.
        Empty list if no patterns were detected.
    """
    warnings = []
    for compiled_pattern, description in _COMPILED_PATTERNS:
        match = compiled_pattern.search(text)
        if match:
            warnings.append(
                f"{description}: matched '{match.group(0)}' at position {match.start()}"
            )
    return warnings


def sanitize_for_llm(text: str, nonce: str | None = None) -> SanitizationResult:
    """Sanitize text for safe use in LLM prompts.

    Scans for prompt injection patterns and wraps the text in a nonce-tagged
    block. The nonce makes the closing tag unpredictable to attackers:

        <user_message_{nonce}>
        {text}
        </user_message_{nonce}>

    The same nonce must appear in the LLM system prompt. Use
    ``build_data_tag(nonce)`` and ``build_data_tag_close(nonce)`` helpers,
    or reference ``result.nonce`` when constructing system prompts.

    Args:
        text: Raw user-sourced text (e.g., a Slack message).
        nonce: Nonce to embed in the tag name. If ``None``, a fresh
            cryptographically random nonce is generated. Pass an explicit
            nonce to share it across all messages in one preprocessing session.

    Returns:
        SanitizationResult with nonce-tagged text, the nonce value,
        risk flag, and warnings.
    """
    if nonce is None:
        nonce = generate_nonce()

    warnings = detect_injection(text)
    has_risk = len(warnings) > 0

    safe_text = f"<user_message_{nonce}>\n{text}\n</user_message_{nonce}>"

    return SanitizationResult(
        text=safe_text,
        nonce=nonce,
        has_risk=has_risk,
        warnings=warnings,
    )


def build_data_tag(nonce: str) -> str:
    """Return the opening data tag for the given nonce.

    Use this when constructing system prompts that reference the data tag.

    Args:
        nonce: The nonce returned in ``SanitizationResult.nonce``.

    Returns:
        Opening tag string, e.g. ``<user_message_3a7f2c1d>``.
    """
    return f"<user_message_{nonce}>"


def build_data_tag_close(nonce: str) -> str:
    """Return the closing data tag for the given nonce.

    Args:
        nonce: The nonce returned in ``SanitizationResult.nonce``.

    Returns:
        Closing tag string, e.g. ``</user_message_3a7f2c1d>``.
    """
    return f"</user_message_{nonce}>"
