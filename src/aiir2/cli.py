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
@click.option("--timezone", default="", help="Timezone for report timestamps (e.g. Asia/Tokyo, overrides AIIR2_TIMEZONE)")
def analyze(
    input_file: str,
    output_dir: str,
    lang: tuple[str, ...],
    project: str,
    location: str,
    model: str,
    timezone: str,
) -> None:
    """Analyze an incident response Slack export.

    Runs the full pipeline: ingest → summarize → activity → roles →
    review → knowledge extraction → translate → render.

    INPUT_FILE is a scat/stail/scli JSON export file.
    """
    from pathlib import Path

    from rich.console import Console

    from aiir2.config import get_gemini_config
    from aiir2.pipeline import run_pipeline

    err = Console(stderr=True)
    try:
        config = get_gemini_config(project=project, location=location, model=model, timezone=timezone)
    except ValueError as e:
        raise click.ClickException(str(e))

    result = run_pipeline(
        input_path=Path(input_file),
        output_dir=output_dir,
        langs=list(lang),
        config=config,
    )

    err.print("\n[bold green]Analysis complete![/bold green]")
    err.print(f"  Output: {result.output_dir}/")
    err.print(f"  Languages: {', '.join(result.languages)}")
    err.print(f"  Tactics: {result.tactic_count}")
    err.print(f"  Messages: {result.message_count}")


@main.group()
def config() -> None:
    """View configuration."""


@config.command("show")
def config_show() -> None:
    """Display current configuration."""
    from aiir2.config import GeminiConfig

    config = GeminiConfig()
    click.echo(f"Project:  {config.project or '(not set)'}")
    click.echo(f"Location: {config.location}")
    click.echo(f"Model:    {config.model}")
    click.echo(f"Timezone: {config.timezone}")
    # Check ADC
    try:
        import google.auth

        creds, _ = google.auth.default()
        click.echo(f"ADC:      configured ({type(creds).__name__})")
    except Exception:
        click.echo("ADC:      not configured (run: gcloud auth application-default login)")
