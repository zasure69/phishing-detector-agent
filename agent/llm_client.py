"""Thin wrapper around the OpenAI-compatible MaaS endpoint.

GreenNode AI Platform exposes an OpenAI-compatible API, so the official
`openai` SDK works against all three self-hosted models (Qwen, Gemma,
MiniMax) by swapping `model` and `base_url`.
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from typing import Any

from openai import OpenAI

from . import config


@lru_cache(maxsize=1)
def _client() -> OpenAI:
    return OpenAI(
        api_key=config.LLM_API_KEY or "not-set",
        base_url=config.LLM_BASE_URL,
        timeout=config.LLM_TIMEOUT_SECONDS,
    )


def chat(
    model: str,
    system: str,
    user: str,
    *,
    temperature: float = 0.2,
    max_tokens: int = 2048,
) -> str:
    """Single-turn chat completion. Returns the assistant text.

    Qwen 3.5 (and other thinking-capable models on the platform) emit a long
    `reasoning` trace that eats the token budget, leaving `content` empty. We
    disable thinking via `chat_template_kwargs.enable_thinking=False` — all
    three project models accept it, and it is far faster (~1.6s vs ~30s).
    """
    kwargs: dict[str, Any] = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    if config.DISABLE_THINKING:
        kwargs["extra_body"] = {"chat_template_kwargs": {"enable_thinking": False}}

    resp = _client().chat.completions.create(**kwargs)
    return (resp.choices[0].message.content or "").strip()


_JSON_FENCE = re.compile(r"```(?:json)?\s*(.*?)\s*```", re.DOTALL)


def extract_json(text: str) -> dict[str, Any]:
    """Best-effort JSON extraction from an LLM response.

    Handles ```json fences and stray prose around the object. Raises
    ValueError if no parseable object is found, so callers can fall back.
    """
    if not text:
        raise ValueError("empty response")

    # 1) fenced block
    m = _JSON_FENCE.search(text)
    candidate = m.group(1) if m else text

    # 2) direct parse
    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        pass

    # 3) first balanced { ... } span
    start = candidate.find("{")
    end = candidate.rfind("}")
    if start != -1 and end != -1 and end > start:
        try:
            return json.loads(candidate[start : end + 1])
        except json.JSONDecodeError:
            pass

    raise ValueError("no parseable JSON in response")


def chat_json(model: str, system: str, user: str, **kw: Any) -> dict[str, Any]:
    """Chat then parse the response as JSON."""
    return extract_json(chat(model, system, user, **kw))
