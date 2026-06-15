"""Phishing Guardian — AgentBase entrypoint.

Exposes the agent over the GreenNode AgentBase HTTP contract:
  GET  /            → web chat UI (normal users paste email/URL/text here)
  POST /invocations → run analysis (or quiz mode)
  GET  /health      → liveness

Payload schema (POST /invocations):
  {"action": "analyze", "content": "<email/url/text>"}   # default action
  {"action": "quiz", "topic": "<optional topic>"}
"""
import os
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv
from greennode_agentbase import (
    GreenNodeAgentBaseApp,
    RequestContext,
    PingStatus,
)
from starlette.responses import HTMLResponse, PlainTextResponse, Response

load_dotenv()

from agent import pipeline, quiz  # noqa: E402

app = GreenNodeAgentBaseApp()

_WEB_DIR = Path(__file__).parent / "web"

# Transparency: the agent must declare it is an AI (rulebook Rule 11.1).
AI_DISCLOSURE = "Bạn đang tương tác với AI — Phishing Guardian."


@app.entrypoint
def handler(payload: dict, context: RequestContext) -> dict:
    """Route an invocation to the analysis pipeline or quiz generator."""
    action = (payload.get("action") or "analyze").lower()
    base = {
        "ai_disclosure": AI_DISCLOSURE,
        "action": action,
        "timestamp": datetime.now().isoformat(),
        "session_id": context.session_id,
    }

    if action == "quiz":
        return {**base, **quiz.generate(payload.get("topic"))}

    if action == "analyze":
        # File upload path: base64-encoded .eml / .msg / .html / .txt.
        b64 = payload.get("content_b64")
        if b64:
            import base64
            try:
                raw_bytes = base64.b64decode(b64)
            except Exception:
                return {**base, "status": "error",
                        "error": "content_b64 không hợp lệ (phải là base64)."}
            from agent import vision
            filename = payload.get("filename")
            mime = vision.sniff_mime(raw_bytes, filename)
            if mime:  # it's an image → screenshot path
                result = pipeline.analyze_image(raw_bytes, filename, mime)
            else:     # email file (.eml/.msg/.html/.txt)
                result = pipeline.analyze_email_file(raw_bytes, filename)
            status = "error" if result.get("error") else "success"
            return {**base, "status": status, **result}

        content = (
            payload.get("content")
            or payload.get("message")
            or payload.get("email")
            or ""
        ).strip()
        if not content:
            return {**base, "status": "error",
                    "error": "Provide 'content' (email/URL/text) or 'content_b64' (file)."}
        result = pipeline.analyze(content)
        status = "error" if result.get("error") else "success"
        return {**base, "status": status, **result}

    return {**base, "status": "error",
            "error": f"Unknown action '{action}'. Use 'analyze' or 'quiz'."}


@app.ping
def health_check() -> PingStatus:
    """GET /health — returns 200 when the server is up."""
    return PingStatus.HEALTHY


async def serve_chat_ui(request):
    """GET / — serve the web chat UI (same origin as /invocations, no CORS)."""
    index = _WEB_DIR / "index.html"
    if not index.exists():
        return PlainTextResponse("Chat UI not found.", status_code=404)
    return HTMLResponse(index.read_text(encoding="utf-8"))


# Register the UI on the root path (and /chat as an alias).
app.add_route("/", serve_chat_ui, methods=["GET"])
app.add_route("/chat", serve_chat_ui, methods=["GET"])


async def teams_messages(request):
    """POST /api/messages — Microsoft Teams (Bot Framework) inbound endpoint."""
    from agent import teams
    auth = request.headers.get("Authorization", "")
    try:
        body = await request.json()
    except Exception:
        return Response(status_code=400)
    status = await teams.handle_activity(body, auth)
    return Response(status_code=status)


app.add_route("/api/messages", teams_messages, methods=["POST"])


if __name__ == "__main__":
    app.run(port=int(os.environ.get("PORT", "8080")), host="0.0.0.0")
