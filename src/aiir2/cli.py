"""Click CLI entry point for ai-ir2."""

from __future__ import annotations

import click

from aiir2 import __version__


@click.group()
@click.version_option(version=__version__, prog_name="aiir2")
def main() -> None:
    """ai-ir2: AI-powered Incident Response analysis — one-stop Gemini pipeline."""


@main.command()
@click.argument("input_file", type=click.Path(exists=True))
@click.option("--output-dir", "-o", default="", help="Output directory (default: ./{incident_id}/)")
@click.option("--lang", "-l", multiple=True, help="Translation languages (e.g. --lang ja --lang zh)")
@click.option("--project", default="", help="GCP project ID (overrides AIIR2_PROJECT)")
@click.option("--location", default="", help="Vertex AI location (overrides AIIR2_LOCATION)")
@click.option("--model", default="", help="Gemini model name (overrides AIIR2_MODEL)")
def analyze(
    input_file: str,
    output_dir: str,
    lang: tuple[str, ...],
    project: str,
    location: str,
    model: str,
) -> None:
    """Analyze an incident response Slack export.

    Runs the full pipeline: ingest → summarize → activity → roles →
    review → knowledge extraction → translate → render.

    INPUT_FILE is a scat/stail/scli JSON export file.
    """
    click.echo("analyze command: not yet implemented")


@main.group()
def config() -> None:
    """View configuration."""


@config.command("show")
def config_show() -> None:
    """Display current configuration."""
    click.echo("config show: not yet implemented")
