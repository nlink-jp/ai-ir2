"""Pipeline orchestrator for ai-ir2."""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path

from rich.console import Console

from aiir2.config import GeminiConfig
from aiir2.llm.client import GeminiClient
from aiir2.models import (
    ActivityAnalysis,
    IncidentReview,
    IncidentSummary,
    IoC,
    PipelineResult,
    ProcessedExport,
    ProcessedMessage,
    RoleAnalysis,
    SlackExport,
    Tactic,
)
from aiir2.parser.defang import defang_text
from aiir2.parser.loader import load_export
from aiir2.parser.sanitizer import generate_nonce, sanitize_for_llm
from aiir2.analyze.summarizer import summarize_incident
from aiir2.analyze.activity import analyze_activity
from aiir2.analyze.roles import analyze_roles
from aiir2.analyze.reviewer import review_incident
from aiir2.knowledge.extractor import extract_tactics
from aiir2.knowledge.formatter import save_tactics, save_tactics_markdown
from aiir2.render.markdown import render_markdown
from aiir2.render.html import render_html
from aiir2.translate.translator import translate_report

logger = logging.getLogger(__name__)
err = Console(stderr=True)


def make_incident_id(channel: str, export_timestamp: str) -> str:
    """Generate a deterministic 12-char incident ID.

    The same source data always produces the same ID, so translated
    versions of a report share an identical incident_id.

    Args:
        channel: Channel name from the export.
        export_timestamp: ISO-format export timestamp string.

    Returns:
        12-character lowercase hex string (48-bit SHA-256 prefix).
    """
    key = f"{channel}|{export_timestamp}"
    return hashlib.sha256(key.encode()).hexdigest()[:12]


def _preprocess(export: SlackExport, nonce: str) -> ProcessedExport:
    """Defang IoCs and sanitize all messages.

    Generates ``ProcessedMessage`` instances with defanged text wrapped
    in nonce-tagged blocks for safe LLM consumption.

    Args:
        export: Raw Slack export.
        nonce: Shared cryptographic nonce for sanitization tags.

    Returns:
        ProcessedExport with defanged IoCs, nonce-tagged sanitized text,
        and the nonce stored in ``sanitization_nonce``.
    """
    processed_messages: list[ProcessedMessage] = []
    all_security_warnings: list[str] = []

    for msg in export.messages:
        # 1. Defang IoCs
        defanged_text, iocs = defang_text(msg.text)

        # 2. Sanitize for LLM (pass shared nonce)
        sanitization = sanitize_for_llm(defanged_text, nonce=nonce)

        if sanitization.has_risk:
            warnings = [f"@{msg.user_name}: {w}" for w in sanitization.warnings]
            all_security_warnings.extend(warnings)
            for w in warnings:
                err.print(f"[red][SECURITY WARNING] Injection risk detected: {w}[/red]")

        if iocs:
            ioc_summary = ", ".join(f"{ioc.type}:{ioc.original}" for ioc in iocs[:5])
            if len(iocs) > 5:
                ioc_summary += f" ... and {len(iocs) - 5} more"
            err.print(
                f"[yellow][DEFANG] @{msg.user_name}: defanged {len(iocs)} IoC(s): {ioc_summary}[/yellow]"
            )

        processed_msg = ProcessedMessage(
            user_id=msg.user_id,
            user_name=msg.user_name,
            post_type=msg.post_type,
            timestamp=msg.timestamp,
            timestamp_unix=msg.timestamp_unix,
            text=sanitization.text,
            files=msg.files,
            thread_timestamp_unix=msg.thread_timestamp_unix,
            is_reply=msg.is_reply,
            iocs=iocs,
            has_injection_risk=sanitization.has_risk,
            injection_warnings=sanitization.warnings,
        )
        processed_messages.append(processed_msg)

    return ProcessedExport(
        export_timestamp=export.export_timestamp,
        channel_name=export.channel_name,
        messages=processed_messages,
        security_warnings=all_security_warnings,
        sanitization_nonce=nonce,
    )


def run_pipeline(
    input_path: Path,
    output_dir: str,
    langs: list[str],
    config: GeminiConfig,
) -> PipelineResult:
    """Run the full analysis pipeline.

    Steps:
        1. Load and preprocess export
        2. Generate incident ID and create output directory
        3. Sequential LLM calls: summarize -> activity -> roles
        4. Build report dict and run review
        5. Extract tactics
        6. Render English (Markdown + HTML)
        7. For each lang: translate -> render translated
        8. Save knowledge files (YAML + MD)
        9. Save preprocessed.json

    Args:
        input_path: Path to scat/stail/scli JSON export file.
        output_dir: Output directory path (empty string for auto).
        langs: List of translation language codes.
        config: Gemini configuration.

    Returns:
        PipelineResult with incident ID and output metadata.
    """
    # 1. Load and preprocess
    raw = load_export(input_path)
    nonce = generate_nonce()
    processed = _preprocess(raw, nonce)
    err.print(f"[dim]Generated sanitization nonce: {nonce[:4]}...{nonce[-4:]}[/dim]")

    # 2. Generate incident ID
    export_ts = processed.export_timestamp.isoformat()
    incident_id = make_incident_id(processed.channel_name, export_ts)

    # Determine output directory
    if not output_dir:
        output_dir = f"./{incident_id}"
    base = Path(output_dir)

    # Create output directories
    (base / "en").mkdir(parents=True, exist_ok=True)
    (base / "knowledge").mkdir(parents=True, exist_ok=True)
    for lang in langs:
        (base / lang).mkdir(parents=True, exist_ok=True)

    # 3. Create LLM client
    client = GeminiClient(config)

    err.print(f"[bold]Incident ID: {incident_id}[/bold]")

    # 4. Parallel analysis (summary, activity, roles, tactics are independent)
    from concurrent.futures import ThreadPoolExecutor, as_completed

    err.print("[dim]Step 1/2: Running parallel analysis (summary + activity + roles + tactics)...[/dim]")

    with ThreadPoolExecutor(max_workers=4) as pool:
        future_summary = pool.submit(summarize_incident, processed, client)
        future_activity = pool.submit(analyze_activity, processed, client)
        future_roles = pool.submit(analyze_roles, processed, client)
        future_tactics = pool.submit(extract_tactics, processed, client)

        summary = future_summary.result()
        activity = future_activity.result()
        roles = future_roles.result()
        tactics = future_tactics.result()

    # 5. Review depends on summary + activity + roles
    report_data = {
        "incident_id": incident_id,
        "metadata": {"channel": processed.channel_name},
        "summary": summary.model_dump(),
        "activity": activity.model_dump(),
        "roles": roles.model_dump(),
    }

    err.print("[dim]Step 2/2: Reviewing process quality...[/dim]")
    review = review_incident(report_data, client)

    # 6. Render
    err.print("[dim]Rendering reports...[/dim]")

    md_en = render_markdown(
        incident_id=incident_id,
        channel=processed.channel_name,
        summary=summary,
        activity=activity,
        roles=roles,
        review=review,
        tactics=tactics,
        export_timestamp=export_ts,
        tz=config.timezone,
    )
    (base / "en" / "report.md").write_text(md_en, encoding="utf-8")

    html_en = render_html(
        incident_id=incident_id,
        channel=processed.channel_name,
        summary=summary,
        activity=activity,
        roles=roles,
        review=review,
        tactics=tactics,
        export_timestamp=export_ts,
        lang="en",
        tz=config.timezone,
    )
    (base / "en" / "report.html").write_text(html_en, encoding="utf-8")

    # 8. Translate and render for each language
    report_dict = {
        "incident_id": incident_id,
        "summary": summary.model_dump(),
        "activity": activity.model_dump(),
        "roles": roles.model_dump(),
        "tactics": [t.model_dump() for t in tactics],
    }
    review_dict = review.model_dump()

    for lang in langs:
        err.print(f"[dim]Translating to {lang}...[/dim]")
        tr_report, tr_review = translate_report(report_dict, review_dict, lang, client)

        # Re-parse translated data for rendering
        tr_summary = IncidentSummary.model_validate(
            tr_report.get("summary", summary.model_dump())
        )
        tr_activity = ActivityAnalysis.model_validate(
            tr_report.get("activity", activity.model_dump())
        )
        tr_roles = RoleAnalysis.model_validate(
            tr_report.get("roles", roles.model_dump())
        )
        tr_review_model = IncidentReview.model_validate(tr_review)
        tr_tactics = [
            Tactic.model_validate(t) for t in tr_report.get("tactics", [])
        ]

        md_tr = render_markdown(
            incident_id=incident_id,
            channel=processed.channel_name,
            summary=tr_summary,
            activity=tr_activity,
            roles=tr_roles,
            review=tr_review_model,
            tactics=tr_tactics,
            export_timestamp=export_ts,
            tz=config.timezone,
        )
        (base / lang / "report.md").write_text(md_tr, encoding="utf-8")

        html_tr = render_html(
            incident_id=incident_id,
            channel=processed.channel_name,
            summary=tr_summary,
            activity=tr_activity,
            roles=tr_roles,
            review=tr_review_model,
            tactics=tr_tactics,
            export_timestamp=export_ts,
            lang=lang,
            tz=config.timezone,
        )
        (base / lang / "report.html").write_text(html_tr, encoding="utf-8")

    # 9. Save knowledge files
    if tactics:
        save_tactics(tactics, base / "knowledge")
        save_tactics_markdown(tactics, base / "knowledge")

    # 10. Save preprocessed.json
    (base / "preprocessed.json").write_text(
        processed.model_dump_json(indent=2), encoding="utf-8"
    )

    return PipelineResult(
        incident_id=incident_id,
        output_dir=str(base),
        languages=["en"] + list(langs),
        tactic_count=len(tactics),
        message_count=len(processed.messages),
    )
