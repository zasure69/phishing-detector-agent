"""Screenshot analysis — read an image of an email/message, then analyze it.

A screenshot only shows what's VISIBLE: the displayed text and displayed URLs,
not the real hyperlink targets, headers, or attachments. So this path is a
convenience fallback (great for SMS / Zalo / Messenger screenshots) that is
inherently weaker than uploading the original .eml — callers should surface
that caveat to the user.
"""
from __future__ import annotations

import base64
from typing import Any

from . import config, prompts
from .llm_client import chat_with_image, extract_json

# Magic-byte signatures for the image types we accept.
_SIGNATURES = (
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
)


def sniff_mime(raw: bytes, filename: str | None = None) -> str | None:
    """Return an image MIME type if the bytes/filename look like an image, else None."""
    for sig, mime in _SIGNATURES:
        if raw.startswith(sig):
            return mime
    if raw[:4] == b"RIFF" and raw[8:12] == b"WEBP":
        return "image/webp"
    ext = (filename or "").lower().rsplit(".", 1)[-1] if "." in (filename or "") else ""
    return {
        "png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg",
        "webp": "image/webp", "gif": "image/gif", "bmp": "image/bmp",
    }.get(ext)


def is_image(raw: bytes, filename: str | None = None) -> bool:
    return sniff_mime(raw, filename) is not None


def extract_from_image(raw: bytes, mime: str = "image/png") -> dict[str, Any]:
    """OCR + visual-cue extraction via the vision model. Returns structured dict."""
    data_url = f"data:{mime};base64,{base64.b64encode(raw).decode()}"
    result = extract_json(
        chat_with_image(
            config.VISION_MODEL,
            prompts.VISION_SYSTEM,
            prompts.VISION_USER,
            data_url,
            max_tokens=2048,
        )
    )
    result.setdefault("reconstructed_text", "")
    result.setdefault("visible_urls", [])
    result.setdefault("visual_red_flags", [])
    return result
