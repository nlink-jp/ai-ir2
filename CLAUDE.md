# ai-ir2 Project Rules

## Purpose

Next-generation incident response Slack conversation analysis tool. Analyzes
scat/stail/scli JSON exports via a single `aiir2 analyze` command to produce
Markdown reports, self-contained HTML, investigation tactic knowledge documents,
and optional translations — all in one invocation.

## Architecture

### Single Pipeline
```
aiir2 analyze <input.json> [--lang ja] [--output-dir DIR]
```

Pipeline stages (sequential):
1. **Ingest** — Load export, defang IoCs, sanitize prompt injection
2. **Summarize** — Generate incident summary (Gemini structured output)
3. **Activity** — Analyze per-participant actions
4. **Roles** — Infer participant roles and relationships
5. **Review** — Assess process quality (phases, communication, checklist)
6. **Knowledge** — Extract reusable investigation tactics
7. **Translate** — Translate narrative fields (if --lang specified)
8. **Render** — Produce Markdown + self-contained HTML for each language

### Module Structure
```
src/aiir2/
  cli.py           - Click CLI: analyze + config show
  config.py        - GeminiConfig (project/location/model, ADC)
  models.py        - All Pydantic data models
  pipeline.py      - Pipeline orchestrator
  utils.py         - format_conversation() etc.
  parser/
    loader.py      - scat/stail/scli JSON export loader
    defang.py      - IoC defanging and extraction
    sanitizer.py   - Prompt injection detection/sanitization
  llm/
    client.py      - Gemini client (google-genai SDK, ADC, response_schema)
  analyze/
    summarizer.py  - Incident summary
    activity.py    - Participant activity analysis
    roles.py       - Role and relationship inference
    reviewer.py    - Process quality review
  knowledge/
    extractor.py   - Tactic extraction
    formatter.py   - YAML + Markdown output
  translate/
    translator.py  - Multi-language translation
  render/
    markdown.py    - Markdown report renderer
    html.py        - Self-contained HTML renderer
    templates/
      report.html  - Jinja2 HTML template (inline CSS/JS)
```

## Security Rules

1. **No external transmission**: Only the configured Vertex AI Gemini endpoint
   may receive data. No analytics, telemetry, or third-party API calls.
2. **Prompt injection defense**: ALL user-sourced text (Slack messages) MUST be
   processed through `sanitizer.sanitize_for_llm()` before LLM prompts.
3. **IoC defanging**: ALL IoCs in Slack messages MUST be defanged via
   `defang.defang_text()` before storage or transmission.
4. **No secret logging**: API keys, tokens, and credentials must never appear
   in logs or output.
5. **Input validation**: All input files are validated against Pydantic models.

## Development Rules

- Small, focused modules — each file has a single clear responsibility
- Tests implemented alongside code in `tests/` directory
- All public functions must have docstrings
- Type hints required for all function signatures
- CHANGELOG.md updated on each feature addition
- No hardcoded credentials or endpoints
- Python with uv virtual environment (`uv sync` to install)
- Run tests: `uv run pytest tests/ -v`

## LLM Configuration

Configure via environment variables (or `.env` file):

```bash
AIIR2_PROJECT=your-gcp-project-id    # Required
AIIR2_LOCATION=us-central1           # Default
AIIR2_MODEL=gemini-2.5-flash         # Default
```

Authentication: Application Default Credentials (ADC).
Run `gcloud auth application-default login` to set up.

## Communication Language

All communication between contributors and Claude Code is conducted in **Japanese**.

## Release Procedure

1. Run tests: `uv run pytest tests/ -v`
2. Update `pyproject.toml` and `src/aiir2/__init__.py` with version
3. Update CHANGELOG.md
4. Commit: `chore: release vX.Y.Z`
5. Tag: `git tag vX.Y.Z`
6. Push: `git push origin main --tags`
7. `gh release create vX.Y.Z` with **English** release notes
