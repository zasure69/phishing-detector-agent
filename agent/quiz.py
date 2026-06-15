"""Quiz Mode — generate a real-vs-phishing email pair for gamified training.

All generated content is synthetic (Rule 9.1: no real internal data).
"""
from __future__ import annotations

from typing import Any

from . import config, prompts
from .llm_client import chat_json

DEFAULT_TOPICS = [
    "cập nhật thông tin lương",
    "cảnh báo đăng nhập bất thường",
    "xác minh giao dịch ngân hàng",
    "nâng cấp tài khoản email công ty",
]


def generate(topic: str | None = None) -> dict[str, Any]:
    """Generate one real + one phishing email about `topic`."""
    chosen = topic or DEFAULT_TOPICS[0]
    if not config.llm_configured():
        return {"error": "LLM not configured. Set LLM_API_KEY and LLM_BASE_URL."}
    try:
        result = chat_json(
            config.QWEN_MODEL,
            prompts.QUIZ_SYSTEM,
            prompts.QUIZ_USER.format(topic=chosen),
            temperature=0.8,
        )
        result["topic"] = chosen
        return result
    except Exception as e:  # noqa: BLE001
        return {"error": f"Quiz generation failed: {e}", "topic": chosen}
