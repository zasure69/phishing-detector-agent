"""Microsoft Teams integration (Bot Framework protocol).

Implements the inbound `/api/messages` contract directly (no heavy SDK):

  1. Validate the JWT that the Bot Connector sends in `Authorization: Bearer ...`
     (signed by the Bot Framework, audience == our app id, issuer == botframework).
  2. Parse the incoming Activity. For a `message`, run the phishing pipeline.
  3. Because analysis takes ~25-40s (longer than Teams' ~15s sync window), we ACK
     immediately (HTTP 200) and reply PROACTIVELY: send "analyzing…", then the
     result, back to the conversation via the Connector REST API.

Outbound auth uses client-credentials (app id + secret) for the
`https://api.botframework.com/.default` scope.
"""
from __future__ import annotations

import asyncio
import re
import time
from typing import Any

import jwt
import requests
from jwt import PyJWKClient

from . import config, pipeline, report, vision

# ── Inbound JWT validation ──
_BF_OPENID = "https://login.botframework.com/v1/.well-known/openidconfiguration"
_BF_ISSUER = "https://api.botframework.com"
_jwk_client: PyJWKClient | None = None


def _jwks() -> PyJWKClient:
    global _jwk_client
    if _jwk_client is None:
        cfg = requests.get(_BF_OPENID, timeout=10).json()
        _jwk_client = PyJWKClient(cfg["jwks_uri"])
    return _jwk_client


def validate_auth_header(auth_header: str) -> bool:
    """Verify the Bot Connector JWT. Returns True only for valid tokens."""
    if not auth_header or not auth_header.startswith("Bearer "):
        return False
    token = auth_header[7:]
    try:
        signing_key = _jwks().get_signing_key_from_jwt(token).key
        jwt.decode(
            token,
            signing_key,
            algorithms=["RS256"],
            audience=config.MICROSOFT_APP_ID,
            issuer=_BF_ISSUER,
            options={"require": ["exp", "iss", "aud"]},
        )
        return True
    except Exception as e:  # noqa: BLE001
        print(f"[teams] JWT validation failed: {type(e).__name__}: {e}", flush=True)
        return False


# ── Outbound: bot token (client credentials), cached until ~expiry ──
_token: dict[str, Any] = {"value": None, "exp": 0.0}


def _bot_token() -> str:
    now = time.time()
    if _token["value"] and now < _token["exp"]:
        return _token["value"]
    resp = requests.post(
        f"https://login.microsoftonline.com/{config.MICROSOFT_APP_TENANT_ID}/oauth2/v2.0/token",
        data={
            "grant_type": "client_credentials",
            "client_id": config.MICROSOFT_APP_ID,
            "client_secret": config.MICROSOFT_APP_PASSWORD,
            "scope": "https://api.botframework.com/.default",
        },
        timeout=15,
    )
    resp.raise_for_status()
    data = resp.json()
    _token["value"] = data["access_token"]
    _token["exp"] = now + int(data.get("expires_in", 3600)) - 60  # refresh 1 min early
    return _token["value"]


def _post_reply(activity: dict, fields: dict) -> None:
    """Post a reply (text or card) back into the originating conversation."""
    service_url = (activity.get("serviceUrl") or "").rstrip("/")
    conv_id = (activity.get("conversation") or {}).get("id")
    if not service_url or not conv_id:
        return
    reply = {
        "type": "message",
        "from": activity.get("recipient"),
        "recipient": activity.get("from"),
        "conversation": activity.get("conversation"),
        **fields,
    }
    try:
        r = requests.post(
            f"{service_url}/v3/conversations/{conv_id}/activities",
            json=reply,
            headers={"Authorization": f"Bearer {_bot_token()}"},
            timeout=20,
        )
        if r.status_code >= 300:
            print(f"[teams] send failed {r.status_code}: {r.text[:200]}", flush=True)
    except Exception as e:  # noqa: BLE001
        print(f"[teams] send error: {e}", flush=True)


def _send_text(activity: dict, text: str) -> None:
    _post_reply(activity, {"text": text, "textFormat": "markdown"})


def _send_card(activity: dict, card: dict) -> None:
    _post_reply(activity, {"attachments": [
        {"contentType": "application/vnd.microsoft.card.adaptive", "content": card}
    ]})


_MENTION_RE = re.compile(r"<at>.*?</at>", re.IGNORECASE | re.DOTALL)


def _clean_text(activity: dict) -> str:
    """Strip the bot @mention Teams prepends in channels."""
    return _MENTION_RE.sub("", activity.get("text") or "").strip()


_BAND_STYLE = {"AN TOÀN": "good", "NGHI NGỜ": "warning", "NGUY HIỂM": "attention"}


def _tb(text: str, **kw) -> dict:
    return {"type": "TextBlock", "text": text, "wrap": True, **kw}


def _build_card(result: dict) -> dict:
    """Render the pipeline result as an Adaptive Card (Teams)."""
    s = result.get("scoring", {})
    r = result.get("report", {})
    band = s.get("band", "")
    style = _BAND_STYLE.get(band, "default")
    color = _BAND_STYLE.get(band, "default")

    body: list[dict] = [{
        "type": "Container", "style": style, "bleed": True, "items": [{
            "type": "ColumnSet", "columns": [
                {"type": "Column", "width": "stretch", "verticalContentAlignment": "Center",
                 "items": [_tb(f"{s.get('emoji','')} {band}", weight="Bolder", size="Large")]},
                {"type": "Column", "width": "auto", "verticalContentAlignment": "Center",
                 "items": [
                     _tb(f"{s.get('safety_score','?')}/100", weight="Bolder", size="ExtraLarge"),
                     _tb("an toàn", size="Small", isSubtle=True, spacing="None"),
                 ]},
            ],
        }],
    }]
    if r.get("verdict_line"):
        body.append(_tb(r["verdict_line"], spacing="Medium"))

    flags = r.get("red_flags", [])
    if flags:
        body.append(_tb("📋 Dấu hiệu phát hiện", weight="Bolder", spacing="Medium"))
        for f in flags[:8]:
            why = f" — {f['why']}" if f.get("why") else ""
            body.append(_tb(f"• **[{f.get('category','?')}]** {f.get('flag','')}{why}",
                            spacing="Small", color=color))
    recs = r.get("recommendations", [])
    if recs:
        body.append(_tb("💡 Khuyến nghị", weight="Bolder", spacing="Medium"))
        for x in recs[:6]:
            body.append(_tb(f"• {x}", spacing="Small"))

    ti = result.get("threat_intel", {})
    if ti.get("enabled") and ti.get("checked"):
        doms = ", ".join(f"{d['domain']} ({d.get('status')})" for d in ti.get("domains", [])[:5])
        body.append(_tb(f"🛡️ VirusTotal: đã kiểm tra {ti['checked']} mục. {doms}",
                        isSubtle=True, size="Small", spacing="Medium"))
    if result.get("caveat"):
        body.append(_tb(f"ℹ️ {result['caveat']}", color="warning", isSubtle=True, size="Small"))
    body.append(_tb("⚠️ Bạn đang tương tác với AI (Phishing Guardian). Kết quả mang tính tham khảo.",
                    isSubtle=True, size="Small", spacing="Medium"))

    return {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.4",
        "body": body,
    }


async def _reply_result(activity: dict, result: dict) -> None:
    if result.get("error"):
        await asyncio.to_thread(_send_text, activity, f"⚠️ {result['error']}")
    else:
        await asyncio.to_thread(_send_card, activity, _build_card(result))


WELCOME = (
    "👋 Xin chào! Mình là **Phishing Guardian** (AI). Hãy **dán nội dung email / URL / "
    "tin nhắn đáng ngờ** vào đây, mình sẽ kiểm tra mức độ lừa đảo và giải thích.\n\n"
    "_⚠️ Bạn đang tương tác với AI._"
)


_FILE_DOWNLOAD = "application/vnd.microsoft.teams.file.download.info"
_MAX_ATTACH_BYTES = 10 * 1024 * 1024  # 10 MB


def _usable_attachment(activity: dict) -> dict | None:
    """Pick the first file/image attachment (ignore the HTML message body)."""
    for a in activity.get("attachments") or []:
        ct = a.get("contentType", "")
        if ct == _FILE_DOWNLOAD or ct.startswith("image/"):
            return a
    return None


def _download_attachment(att: dict) -> tuple[bytes, str] | None:
    """Download a Teams attachment. Returns (bytes, filename) or None."""
    ct = att.get("contentType", "")
    name = att.get("name") or ""
    if ct == _FILE_DOWNLOAD:
        url = (att.get("content") or {}).get("downloadUrl")
        if not url:
            return None
        r = requests.get(url, timeout=30)  # pre-signed URL, no auth header needed
    elif ct.startswith("image/"):
        url = att.get("contentUrl")
        if not url:
            return None
        # Teams-hosted images require the bot token; fall back to anonymous.
        r = requests.get(url, headers={"Authorization": f"Bearer {_bot_token()}"}, timeout=30)
        if r.status_code >= 300:
            r = requests.get(url, timeout=30)
        if not name:
            name = f"image.{ct.split('/')[-1] or 'png'}"
    else:
        return None
    r.raise_for_status()
    if len(r.content) > _MAX_ATTACH_BYTES:
        raise ValueError("file quá lớn (>10MB)")
    return r.content, name


def _analyze_payload(raw: bytes, name: str) -> dict:
    """Route downloaded bytes to the right pipeline path (image / email / text)."""
    if vision.sniff_mime(raw, name):
        return pipeline.analyze_image(raw, name, vision.sniff_mime(raw, name))
    ext = name.lower().rsplit(".", 1)[-1] if "." in name else ""
    if ext in ("eml", "msg", "html", "htm", "mime"):
        return pipeline.analyze_email_file(raw, name)
    try:
        return pipeline.analyze(raw.decode("utf-8", errors="replace"))
    except Exception:  # noqa: BLE001
        return pipeline.analyze_email_file(raw, name)


async def _process(activity: dict) -> None:
    """Background: analyze the message (text or attachment) and reply proactively."""
    att = _usable_attachment(activity)

    if att is not None:
        await asyncio.to_thread(_send_text, activity, "⏳ Đang tải & phân tích tệp, chờ chút…")
        try:
            got = await asyncio.to_thread(_download_attachment, att)
            if not got:
                await asyncio.to_thread(_send_text, activity, "⚠️ Không tải được tệp đính kèm.")
                return
            raw, name = got
            result = await asyncio.to_thread(_analyze_payload, raw, name)
            await _reply_result(activity, result)
        except Exception as e:  # noqa: BLE001
            print(f"[teams] attachment error: {e}", flush=True)
            await asyncio.to_thread(_send_text, activity, f"⚠️ Không xử lý được tệp: {e}")
        return

    text = _clean_text(activity)
    if not text:
        await asyncio.to_thread(
            _send_text, activity,
            "Hãy dán nội dung email/URL/tin nhắn đáng ngờ, hoặc đính kèm file .eml/.msg/ảnh chụp màn hình.")
        return
    await asyncio.to_thread(_send_text, activity, "⏳ Đang phân tích qua AI, chờ chút…")
    try:
        result = await asyncio.to_thread(pipeline.analyze, text)
        await _reply_result(activity, result)
    except Exception as e:  # noqa: BLE001
        print(f"[teams] pipeline error: {e}", flush=True)
        await asyncio.to_thread(_send_text, activity, "⚠️ Có lỗi khi phân tích. Vui lòng thử lại.")


async def handle_activity(body: dict, auth_header: str) -> int:
    """Entry point for POST /api/messages. Returns the HTTP status to reply with."""
    if not config.teams_configured():
        return 503
    if not validate_auth_header(auth_header):
        return 401

    activity_type = body.get("type")
    if activity_type == "message":
        _spawn(_process(body))   # ACK now, reply later
        return 200
    if activity_type == "conversationUpdate":
        for m in body.get("membersAdded", []) or []:
            if m.get("id") != (body.get("recipient") or {}).get("id"):
                _spawn(asyncio.to_thread(_send_text, body, WELCOME))
                break
        return 200
    return 200  # ignore other activity types


_bg_tasks: set = set()


def _spawn(coro) -> None:
    """Fire-and-forget a coroutine, keeping a reference so it isn't GC'd."""
    task = asyncio.create_task(coro)
    _bg_tasks.add(task)
    task.add_done_callback(_bg_tasks.discard)
