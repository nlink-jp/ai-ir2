# ai-ir2

Next-generation AI-powered incident response analysis tool.

- **Language**: Python 3.11+ / uv
- **LLM**: Vertex AI Gemini (google-genai SDK, ADC auth)
- **Series**: cybersecurity-series
- **CLI**: `aiir2 analyze <input.json> [--lang ja] [--output-dir DIR]`
- **Output**: Markdown + self-contained HTML + YAML/MD knowledge docs
- **Input**: scat/stail/scli JSON export (shared EXPORT_FORMAT.md schema)
