"""Final report synthesis (Qwen) + deterministic fallback / text rendering."""
from __future__ import annotations

import json
from typing import Any

from . import config, prompts
from .llm_client import chat_json
from .parser import ParsedInput


def _deterministic_flags(
    parsed: ParsedInput, qwen: dict[str, Any], gemma: dict[str, Any]
) -> list[dict[str, str]]:
    """Build red flags from structured data when the LLM synth is unavailable."""
    flags: list[dict[str, str]] = []
    for t in qwen.get("social_engineering_tactics", [])[:4]:
        if isinstance(t, dict) and t.get("tactic"):
            flags.append({"category": "Ngôn ngữ", "flag": t["tactic"],
                          "why": t.get("evidence", "")})
    for u in parsed.urls:
        if u.suspicious_tld:
            flags.append({"category": "URL",
                          "flag": f"Tên miền đáng ngờ: {u.domain}",
                          "why": f"TLD '.{u.tld}' thường bị lạm dụng cho phishing"})
    if parsed.is_freemail and parsed.sender_domain:
        flags.append({"category": "Header",
                      "flag": f"Gửi từ email cá nhân ({parsed.sender_domain})",
                      "why": "Tổ chức thật hiếm khi dùng email miễn phí"})
    return flags


def _merge_flags(*flag_lists: list[dict[str, str]]) -> list[dict[str, str]]:
    """Concatenate flag lists, dropping duplicates by their 'flag' text."""
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for lst in flag_lists:
        for f in lst or []:
            key = (f.get("flag") or "").strip().lower()
            if key and key not in seen:
                seen.add(key)
                out.append(f)
    return out


def synthesize(
    parsed: ParsedInput,
    scoring: dict[str, Any],
    qwen: dict[str, Any],
    gemma: dict[str, Any],
    minimax: dict[str, Any],
) -> dict[str, Any]:
    """Produce verdict_line / red_flags / recommendations (Vietnamese)."""
    try:
        report = chat_json(
            config.QWEN_MODEL,
            prompts.QWEN_REPORT_SYSTEM,
            prompts.QWEN_REPORT_USER.format(
                risk_score=scoring["final_score"],
                risk_band=scoring["band"],
                qwen=json.dumps(qwen, ensure_ascii=False),
                gemma=json.dumps(gemma, ensure_ascii=False),
                minimax=json.dumps(minimax, ensure_ascii=False),
            ),
        )
        report.setdefault("red_flags", [])
        report.setdefault("recommendations", [])
        llm_flags = report["red_flags"] or _deterministic_flags(parsed, qwen, gemma)
        # Deterministic findings (real link mismatch, dangerous attachment,
        # auth failure) are factual — always surface them first.
        report["red_flags"] = _merge_flags(parsed.deterministic_flags, llm_flags)
        return report
    except Exception:  # noqa: BLE001 — fall back to deterministic report
        band = scoring["band"]
        return {
            "verdict_line": f"Mức độ {band} ({scoring['final_score']}/100).",
            "red_flags": _merge_flags(
                parsed.deterministic_flags,
                _deterministic_flags(parsed, qwen, gemma),
            ),
            "recommendations": [
                "Không click vào bất kỳ link nào trong nội dung.",
                "Không cung cấp thông tin cá nhân, mật khẩu, OTP.",
                "Xác minh với tổ chức qua kênh chính thức nếu nghi ngờ.",
            ],
            "synth_fallback": True,
        }


def render_text(result: dict[str, Any]) -> str:
    """Render a human-readable Vietnamese report (for CLI / chat display)."""
    s = result["scoring"]
    r = result["report"]
    lines = [
        f"{s['emoji']} MỨC ĐỘ {s['band']}: {s['final_score']}/100",
        "",
        r.get("verdict_line", ""),
        "",
        "📋 CÁC DẤU HIỆU PHÁT HIỆN:",
    ]
    flags = r.get("red_flags", [])
    if flags:
        for i, f in enumerate(flags, 1):
            lines.append(f"{i}. [{f.get('category', '?')}] {f.get('flag', '')}"
                         + (f" — {f['why']}" if f.get("why") else ""))
    else:
        lines.append("(không phát hiện dấu hiệu rõ ràng)")
    lines += ["", "💡 KHUYẾN NGHỊ:"]
    for rec in r.get("recommendations", []):
        lines.append(f"- {rec}")
    lines += ["", "⚠️ Bạn đang tương tác với AI (Phishing Guardian)."]
    return "\n".join(lines)
