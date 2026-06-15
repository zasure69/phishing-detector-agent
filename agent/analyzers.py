"""Per-model analysis functions.

Each analyzer calls one model with a role-specific prompt and returns a
normalized dict. Every analyzer is defensive: on LLM error or unparseable
output it returns a structured fallback with an `error` field rather than
raising, so the pipeline can still produce a result.
"""
from __future__ import annotations

import json
from typing import Any

from . import config, prompts
from .llm_client import chat_json
from .parser import ParsedInput


def _fallback(score_key: str, error: str) -> dict[str, Any]:
    return {score_key: 0, "critical": False, "error": error}


def analyze_language(parsed: ParsedInput) -> dict[str, Any]:
    """Qwen — Vietnamese social-engineering / language analysis."""
    try:
        result = chat_json(
            config.QWEN_MODEL,
            prompts.QWEN_LANGUAGE_SYSTEM,
            prompts.QWEN_LANGUAGE_USER.format(content=parsed.raw),
        )
        result.setdefault("overall_language_risk_score", 0)
        result.setdefault("critical", False)
        return result
    except Exception as e:  # noqa: BLE001 — degrade gracefully
        return _fallback("overall_language_risk_score", str(e))


def analyze_technical(parsed: ParsedInput) -> dict[str, Any]:
    """Gemma — structured technical indicator extraction."""
    hints = json.dumps(
        {
            "input_type": parsed.input_type,
            "sender_email": parsed.sender_email,
            "sender_domain": parsed.sender_domain,
            "is_freemail": parsed.is_freemail,
            "urls": [
                {"url": u.raw, "domain": u.domain, "tld": u.tld,
                 "suspicious_tld": u.suspicious_tld}
                for u in parsed.urls
            ],
        },
        ensure_ascii=False,
    )
    try:
        result = chat_json(
            config.GEMMA_MODEL,
            prompts.GEMMA_TECH_SYSTEM,
            prompts.GEMMA_TECH_USER.format(hints=hints, content=parsed.raw),
        )
        result.setdefault("technical_risk_score", 0)
        result.setdefault("critical", False)
        return result
    except Exception as e:  # noqa: BLE001
        return _fallback("technical_risk_score", str(e))


def cross_validate(
    parsed: ParsedInput, qwen: dict[str, Any], gemma: dict[str, Any]
) -> dict[str, Any]:
    """MiniMax — independent cross-validation (text mode)."""
    if not config.MINIMAX_ENABLED:
        return {"visual_risk_score": 0, "critical": False, "skipped": True}
    try:
        result = chat_json(
            config.MINIMAX_MODEL,
            prompts.MINIMAX_CROSSVAL_SYSTEM,
            prompts.MINIMAX_CROSSVAL_USER.format(
                qwen=json.dumps(qwen, ensure_ascii=False),
                gemma=json.dumps(gemma, ensure_ascii=False),
                content=parsed.raw,
            ),
        )
        result.setdefault("visual_risk_score", 0)
        result.setdefault("critical", False)
        return result
    except Exception as e:  # noqa: BLE001
        return _fallback("visual_risk_score", str(e))
