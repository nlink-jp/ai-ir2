# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-04-06

### Added

- **One-stop analysis pipeline** — `aiir2 analyze` runs ingest, summarize, activity analysis, role inference, process review, tactic extraction, translation, and rendering in a single command
- **Vertex AI Gemini integration** — `google-genai` SDK with ADC authentication and structured output via `response_schema`
- **Self-contained HTML reports** — Single-file HTML with inline CSS/JS and tab navigation (no external CDN dependencies)
- **Markdown reports** — Combined report with summary, timeline, activities, roles, review, and tactics
- **Knowledge documents** — YAML and Markdown tactic files for investigation knowledge reuse
- **Built-in translation** — `--lang` flag for multi-language output (ja, zh, ko, de, fr, es); English always produced
- **Incident-ID-based output** — Deterministic directory structure grouping all artifacts
- **Security pipeline** — IoC defanging and nonce-tagged prompt injection defense (ported from ai-ir)
- **Exponential backoff retry** — Rate limit handling for Gemini API calls
- **`config show` command** — Display GCP project, location, model, and ADC status
