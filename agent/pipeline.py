"""End-to-end orchestration of the phishing analysis pipeline.

Flow:  parse  →  (Qwen language ‖ Gemma technical)  →  MiniMax cross-validate
       →  risk scoring  →  Qwen report synthesis  →  rendered output.

Qwen and Gemma run concurrently since they're independent; MiniMax depends
on both, so it runs after they return.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Any

from . import analyzers, config, eml_parser, report, scoring, threat_intel
from .parser import ParsedInput, parse


def _run(parsed: ParsedInput) -> dict[str, Any]:
    """Run the full pipeline on an already-parsed input."""
    if not config.llm_configured():
        return {
            "error": "LLM not configured. Set LLM_API_KEY (see /agentbase-llm) "
                     "and LLM_BASE_URL.",
            "parsed": parsed.to_dict(),
        }

    # Stage 1: independent analyses + VirusTotal enrichment, all in parallel.
    # VT runs alongside the LLMs so its network latency overlaps theirs.
    with ThreadPoolExecutor(max_workers=3) as pool:
        f_lang = pool.submit(analyzers.analyze_language, parsed)
        f_tech = pool.submit(analyzers.analyze_technical, parsed)
        f_vt = pool.submit(threat_intel.enrich, parsed)
        qwen = f_lang.result()
        gemma = f_tech.result()
        vt_flags, vt_critical, vt_summary = f_vt.result()

    # Stage 2: cross-validation (depends on stage 1).
    minimax = analyzers.cross_validate(parsed, qwen, gemma)

    # Fold VirusTotal findings into the deterministic layer (surfaced first —
    # ground-truth reputation is the strongest signal we have).
    parsed.deterministic_flags = vt_flags + parsed.deterministic_flags
    parsed.deterministic_critical = parsed.deterministic_critical or vt_critical

    # Stage 3: aggregate. Deterministic findings (VT detections, link mismatch,
    # dangerous attachment, auth failure) can independently force critical.
    score_detail = scoring.score(
        qwen, gemma, minimax, force_critical=parsed.deterministic_critical
    )

    # Stage 4: synthesize the user-facing report.
    rep = report.synthesize(parsed, score_detail, qwen, gemma, minimax)

    result = {
        "parsed": parsed.to_dict(),
        "analysis": {"language": qwen, "technical": gemma, "cross_validation": minimax},
        "threat_intel": vt_summary,
        "scoring": score_detail,
        "report": rep,
    }
    result["display"] = report.render_text(result)
    return result


def analyze(raw: str) -> dict[str, Any]:
    """Run the full pipeline on raw pasted content (text / URL / pasted email)."""
    return _run(parse(raw))


def analyze_email_file(raw_bytes: bytes, filename: str | None = None) -> dict[str, Any]:
    """Run the pipeline on an uploaded email file (.eml / .msg / .html / .txt).

    Recovers real hyperlink targets, true headers, and attachment metadata
    that copy-paste would lose.
    """
    try:
        parsed = eml_parser.parse_file(raw_bytes, filename)
    except ValueError as e:
        return {"error": str(e)}
    except Exception as e:  # noqa: BLE001
        return {"error": f"Không đọc được file: {e}"}
    return _run(parsed)
