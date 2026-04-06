# ai-ir2: AI-powered Incident Response Analysis

[日本語](README.ja.md)

`ai-ir2` analyzes incident response Slack conversation history exported via
[scat](https://github.com/nlink-jp/scat), [stail](https://github.com/nlink-jp/stail),
or [scli](https://github.com/nlink-jp/scli) and produces a comprehensive analysis report
in a single command.

Powered by **Vertex AI Gemini** with Application Default Credentials.

## Features

- **One-stop analysis** — Single `aiir2 analyze` command runs the full pipeline: ingest, summarize, activity analysis, role inference, process review, and tactic extraction
- **Multi-format output** — Markdown reports, self-contained HTML (shareable single file), and YAML/Markdown knowledge documents
- **Built-in translation** — Specify `--lang ja` (or zh, ko, de, fr, es) at invocation; English version always produced
- **Security-first** — IoC defanging, prompt injection defense with nonce-tagged wrapping
- **Vertex AI Gemini** — Structured output via `response_schema`, ADC authentication

## Prerequisites

- Python 3.11+
- [uv](https://docs.astral.sh/uv/) package manager
- GCP project with Vertex AI API enabled
- Application Default Credentials: `gcloud auth application-default login`

## Installation

```bash
uv sync
```

## Quick Start

```bash
# Export Slack channel history
stail export -c "#incident-response" --output incident.json

# Run full analysis (English + Japanese)
aiir2 analyze incident.json --lang ja

# Output directory structure:
# {incident_id}/
# ├── en/report.md, report.html
# ├── ja/report.md, report.html
# ├── knowledge/*.yaml, *.md
# └── preprocessed.json
```

## Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `AIIR2_PROJECT` | (required) | GCP project ID |
| `AIIR2_LOCATION` | `us-central1` | Vertex AI location |
| `AIIR2_MODEL` | `gemini-2.5-flash` | Gemini model name |

CLI flags `--project`, `--location`, `--model` override environment variables.

## Commands

```bash
aiir2 analyze <input.json>          # Full analysis pipeline
aiir2 analyze <input.json> --lang ja --lang zh  # With translation
aiir2 analyze <input.json> -o ./out  # Custom output directory
aiir2 config show                    # Display current configuration
```

## Documentation

- [Data Format](docs/en/data-format.md) / [データフォーマット](docs/ja/data-format.md)

## License

MIT
