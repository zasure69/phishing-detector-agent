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


def _send_text(activity: dict, text: str) -> None:
    """Send a reply message back into the originating conversation."""
    service_url = (activity.get("serviceUrl") or "").rstrip("/")
    conv_id = (activity.get("conversation") or {}).get("id")
    if not service_url or not conv_id:
        return
    reply = {
        "type": "message",
        "from": activity.get("recipient"),
        "recipient": activity.get("from"),
        "conversation": activity.get("conversation"),
        "text": text,
        "textFormat": "markdown",
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


_MENTION_RE = re.compile(r"<at>.*?</at>", re.IGNORECASE | re.DOTALL)


def _clean_text(activity: dict) -> str:
    """Strip the bot @mention Teams prepends in channels."""
    return _MENTION_RE.sub("", activity.get("text") or "").strip()


def _format_reply(result: dict) -> str:
    """Render the pipeline result as Teams markdown."""
    s = result.get("scoring", {})
    r = result.get("report", {})
    lines = [f"{s.get('emoji','')} **{s.get('band','')} — {s.get('final_score','?')}/100**"]
    if r.get("verdict_line"):
        lines += ["", r["verdict_line"]]
    flags = r.get("red_flags", [])
    if flags:
        lines += ["", "**📋 Dấu hiệu phát hiện:**"]
        for f in flags[:8]:
            why = f" — {f['why']}" if f.get("why") else ""
            lines.append(f"- **[{f.get('category','?')}]** {f.get('flag','')}{why}")
    recs = r.get("recommendations", [])
    if recs:
        lines += ["", "**💡 Khuyến nghị:**"]
        lines += [f"- {x}" for x in recs[:6]]
    ti = result.get("threat_intel", {})
    if ti.get("enabled") and ti.get("checked"):
        doms = ", ".join(f"{d['domain']} ({d.get('status')})" for d in ti.get("domains", [])[:5])
        lines += ["", f"_🛡️ VirusTotal đã kiểm tra {ti['checked']} mục._" + (f" {doms}" if doms else "")]
    if result.get("caveat"):
        lines += ["", f"_ℹ️ {result['caveat']}_"]
    lines += ["", "_⚠️ Bạn đang tương tác với AI (Phishing Guardian). Kết quả mang tính tham khảo._"]
    return "\n\n".join(lines)


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
            msg = f"⚠️ {result['error']}" if result.get("error") else _format_reply(result)
        except Exception as e:  # noqa: BLE001
            print(f"[teams] attachment error: {e}", flush=True)
            msg = f"⚠️ Không xử lý được tệp: {e}"
        await asyncio.to_thread(_send_text, activity, msg)
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
        if result.get("error"):
            msg = f"⚠️ {result['error']}"
        else:
            msg = _format_reply(result)
    except Exception as e:  # noqa: BLE001
        print(f"[teams] pipeline error: {e}", flush=True)
        msg = "⚠️ Có lỗi khi phân tích. Vui lòng thử lại."
    await asyncio.to_thread(_send_text, activity, msg)


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
