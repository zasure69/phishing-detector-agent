"""Risk scoring engine — weighted aggregation with a critical-flag floor.

Combines the three model scores into a single 0-100 risk value and maps it
to a band (SAFE / SUSPICIOUS / DANGEROUS). Implements the rule from the
brief: if ANY model flags a critical indicator, the score floors at 70.
"""
from __future__ import annotations

from typing import Any

from . import config

BAND_SAFE = "AN TOÀN"
BAND_SUSPICIOUS = "NGHI NGỜ"
BAND_DANGEROUS = "NGUY HIỂM"

_BAND_EMOJI = {
    BAND_SAFE: "🟢",
    BAND_SUSPICIOUS: "🟡",
    BAND_DANGEROUS: "🔴",
}


def _clamp(v: Any) -> float:
    try:
        n = float(v)
    except (TypeError, ValueError):
        return 0.0
    return max(0.0, min(100.0, n))


def band_for(score: float) -> str:
    if score <= config.SAFE_MAX:
        return BAND_SAFE
    if score <= config.SUSPICIOUS_MAX:
        return BAND_SUSPICIOUS
    return BAND_DANGEROUS


def emoji_for(band: str) -> str:
    return _BAND_EMOJI.get(band, "⚪")


def score(
    qwen: dict[str, Any],
    gemma: dict[str, Any],
    minimax: dict[str, Any],
    *,
    force_critical: bool = False,
) -> dict[str, Any]:
    """Return aggregated scoring detail.

    The visual/cross-validation weight is redistributed to the other two
    components when MiniMax is skipped, so a missing third model never
    silently drags the score down. `force_critical` lets deterministic
    findings (link mismatch, dangerous attachment, SPF/DKIM fail) floor the
    verdict into the DANGEROUS band regardless of the model scores.
    """
    lang = _clamp(qwen.get("overall_language_risk_score"))
    tech = _clamp(gemma.get("technical_risk_score"))
    vis = _clamp(minimax.get("visual_risk_score"))

    w = dict(config.WEIGHTS)
    minimax_used = not minimax.get("skipped")
    if not minimax_used:
        # Redistribute the visual weight proportionally to language+technical.
        spare = w.pop("visual")
        total = w["language"] + w["technical"]
        w["language"] += spare * (w["language"] / total)
        w["technical"] += spare * (w["technical"] / total)
        vis = 0.0

    weighted = lang * w["language"] + tech * w["technical"]
    if minimax_used:
        weighted += vis * w["visual"]
    final = round(weighted, 1)

    critical = bool(
        force_critical
        or qwen.get("critical") or gemma.get("critical") or minimax.get("critical")
    )
    floored = False
    if critical and final < config.CRITICAL_FLOOR:
        final = float(config.CRITICAL_FLOOR)
        floored = True

    band = band_for(final)
    return {
        "final_score": final,                 # RISK (internal): higher = more dangerous
        "safety_score": round(100 - final, 1),  # DISPLAY: higher = safer
        "band": band,
        "emoji": emoji_for(band),
        "critical": critical,
        "critical_floor_applied": floored,
        "components": {
            "language": lang,
            "technical": tech,
            "visual": vis,
        },
        "weights": w,
        "minimax_used": minimax_used,
    }
