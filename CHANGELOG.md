# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-04-06

### Added

- **Parallel LLM calls** — Summary, activity, roles, and tactics extraction run concurrently via ThreadPoolExecutor (review remains sequential as it depends on the first three)
- **Timezone configuration** — `AIIR2_TIMEZONE` env var and `--timezone` CLI option for report timestamps (IANA names, e.g. `Asia/Tokyo`)
- **Analysis methodology documentation** — `docs/en/analysis-methodology.md` and `docs/ja/analysis-methodology.md` with actual LLM system prompts, output schemas, and detailed evaluation criteria tables
- **Data format documentation** — `docs/en/data-format.md` and `docs/ja/data-format.md`
- **Simulation test data** — 31-message, 11-participant IR scenario with incorrect actions

### Fixed

- Prevent `@@` double-prefix on user names when LLM returns `@`-prefixed names
- Normalize badge CSS class names to lowercase (LLM returns varying capitalization)
- HTML report layout: unified spacing via flexbox gap, consistent grid card heights, tab bar without scrollbar, active tab indicator visibility
- Summary layout: Root Cause / Resolution above Timeline
- Activity tab: per-participant card layout with unified column widths
- Color palette warmed from slate to gray (matching ai-ir)
- Export timestamp converted to configured timezone (was raw UTC)
- LICENSE copyright holder corrected to magifd2

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
