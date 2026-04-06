"""Format tactics as YAML or Markdown knowledge documents."""

from __future__ import annotations

from pathlib import Path

import yaml

from aiir2.models import Tactic


def tactic_to_yaml(tactic: Tactic) -> str:
    """Convert a Tactic to a YAML string.

    Args:
        tactic: Tactic model to serialize.

    Returns:
        YAML-formatted string representing the tactic.
    """
    data = {
        "id": tactic.id,
        "title": tactic.title,
        "confidence": tactic.confidence,
        "evidence": tactic.evidence,
        "purpose": tactic.purpose,
        "category": tactic.category,
        "tools": tactic.tools,
        "procedure": tactic.procedure,
        "observations": tactic.observations,
        "tags": tactic.tags,
        "source": {
            "channel": tactic.source.channel,
            "participants": tactic.source.participants,
        },
        "created_at": tactic.created_at,
    }
    return yaml.dump(data, default_flow_style=False, allow_unicode=True, sort_keys=False)


def tactic_to_markdown(tactic: Tactic) -> str:
    """Convert a Tactic to a Markdown string suitable for RAG ingestion.

    Each tactic is rendered as a self-contained Markdown document with one
    H1 title and H2 sections.  The structure is optimised for semantic
    chunking: every section carries independent meaning so a RAG retriever
    can surface the tactic from any angle (tool name, symptom, procedure
    step, etc.).

    Args:
        tactic: Tactic model to serialize.

    Returns:
        Markdown-formatted string representing the tactic.
    """
    tags_str = ", ".join(f"`{t}`" for t in tactic.tags) if tactic.tags else "—"
    tools_str = "\n".join(f"- `{t}`" for t in tactic.tools) if tactic.tools else "- —"
    participants_str = ", ".join(tactic.source.participants) if tactic.source.participants else "—"

    lines = [
        f"# {tactic.title}",
        "",
        f"**ID:** {tactic.id} | **Category:** `{tactic.category}` | "
        f"**Confidence:** {tactic.confidence}",
        f"**Tags:** {tags_str}",
        f"**Source:** {tactic.source.channel} ({participants_str}) — {tactic.created_at}",
        "",
        "## Purpose",
        "",
        tactic.purpose,
        "",
        "## Tools",
        "",
        tools_str,
        "",
        "## Procedure",
        "",
        tactic.procedure,
        "",
        "## Observations",
        "",
        tactic.observations,
    ]

    if tactic.evidence:
        lines += [
            "",
            "## Evidence",
            "",
            tactic.evidence,
        ]

    return "\n".join(lines) + "\n"


def save_tactics_markdown(tactics: list[Tactic], output_dir: Path) -> list[Path]:
    """Save tactics as individual Markdown files for RAG ingestion.

    Each tactic is saved to a file named ``{id}-{title-slug}.md``.
    The slug generation mirrors :func:`save_tactics` for consistency.

    Args:
        tactics: List of Tactic objects to save.
        output_dir: Directory to save Markdown files to (created if it doesn't exist).

    Returns:
        List of Paths to the saved Markdown files.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    saved = []
    for tactic in tactics:
        title_slug = tactic.title.lower().replace(" ", "-")
        title_slug = "".join(c for c in title_slug if c.isalnum() or c == "-")
        title_slug = title_slug[:30].rstrip("-")

        filename = f"{tactic.id}-{title_slug}.md"
        path = output_dir / filename
        path.write_text(tactic_to_markdown(tactic), encoding="utf-8")
        saved.append(path)
    return saved


def save_tactics(tactics: list[Tactic], output_dir: Path) -> list[Path]:
    """Save tactics as individual YAML files.

    Each tactic is saved to a file named ``{id}-{title-slug}.yaml``.

    Args:
        tactics: List of Tactic objects to save.
        output_dir: Directory to save YAML files to (created if it doesn't exist).

    Returns:
        List of Paths to the saved YAML files.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    saved = []
    for tactic in tactics:
        # Create a URL-friendly slug from the title
        title_slug = tactic.title.lower().replace(" ", "-")
        # Remove non-alphanumeric characters except hyphens
        title_slug = "".join(c for c in title_slug if c.isalnum() or c == "-")
        # Truncate to 30 chars
        title_slug = title_slug[:30].rstrip("-")

        filename = f"{tactic.id}-{title_slug}.yaml"
        path = output_dir / filename
        path.write_text(tactic_to_yaml(tactic), encoding="utf-8")
        saved.append(path)
    return saved
