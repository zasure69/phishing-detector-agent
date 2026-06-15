"""Build the Microsoft Teams app package (manifest.json + icons -> zip).

Run:  python teams/make_package.py

Produces in teams/:
  - color.png  (192x192)  app icon
  - outline.png (32x32)   transparent outline icon
  - manifest.json         Teams app manifest (bot wired to MICROSOFT_APP_ID)
  - phishing-guardian-teams.zip   <- upload this to Teams

Edit BOT_ID / ENDPOINT_DOMAIN below if they change.
"""
import json
import os
import zipfile

from PIL import Image, ImageDraw

HERE = os.path.dirname(os.path.abspath(__file__))

# ── Fill these from your Azure Bot / AgentBase deployment ──
BOT_ID = "53095134-5a70-4a33-ada7-e12a13cacee5"          # = Microsoft App ID
ENDPOINT_DOMAIN = "endpoint-e93cb03b-ed4f-4eec-ae08-a4291fd22e18.agentbase-runtime.aiplatform.vngcloud.vn"
TEAMS_APP_ID = "8f3b1c2e-4d5a-4e6f-9a7b-1c2d3e4f5a6b"     # any GUID, distinct from BOT_ID
ACCENT = "#4F8CFF"

_SHIELD = [(96, 16), (168, 44), (168, 100), (96, 176), (24, 100), (24, 44)]


def _shield_scaled(size, pad):
    s = size / 192.0
    pts = [(x * s, y * s) for (x, y) in _SHIELD]
    return pts


def make_color_icon(path):
    img = Image.new("RGBA", (192, 192), (11, 16, 32, 255))  # dark bg
    d = ImageDraw.Draw(img)
    d.polygon(_SHIELD, fill=ACCENT)
    # simple check mark inside the shield
    d.line([(70, 96), (90, 120), (128, 70)], fill="white", width=12, joint="curve")
    img.save(path)


def make_outline_icon(path):
    img = Image.new("RGBA", (32, 32), (0, 0, 0, 0))  # transparent
    d = ImageDraw.Draw(img)
    pts = [(16, 3), (28, 8), (28, 17), (16, 29), (4, 17), (4, 8)]
    d.line(pts + [pts[0]], fill="white", width=2, joint="curve")
    img.save(path)


MANIFEST = {
    "$schema": "https://developer.microsoft.com/en-us/json-schemas/teams/v1.17/MicrosoftTeams.schema.json",
    "manifestVersion": "1.17",
    "version": "1.0.0",
    "id": TEAMS_APP_ID,
    "developer": {
        "name": "VNG - Phishing Guardian",
        "websiteUrl": f"https://{ENDPOINT_DOMAIN}",
        "privacyUrl": f"https://{ENDPOINT_DOMAIN}/",
        "termsOfUseUrl": f"https://{ENDPOINT_DOMAIN}/",
    },
    "name": {
        "short": "Phishing Guardian",
        "full": "Phishing Guardian - AI phishing detector",
    },
    "description": {
        "short": "AI phát hiện email/tin nhắn lừa đảo (tiếng Việt).",
        "full": ("Dán email / URL / tin nhắn đáng ngờ, Phishing Guardian (AI) sẽ phân tích "
                 "mức độ rủi ro, chỉ ra dấu hiệu lừa đảo và khuyến nghị hành động. "
                 "Bạn đang tương tác với AI; công cụ không lưu dữ liệu thật."),
    },
    "icons": {"color": "color.png", "outline": "outline.png"},
    "accentColor": ACCENT,
    "bots": [
        {
            "botId": BOT_ID,
            "scopes": ["personal", "team", "groupChat"],
            "supportsFiles": True,
            "isNotificationOnly": False,
        }
    ],
    "permissions": ["identity", "messageTeamMembers"],
    "validDomains": [ENDPOINT_DOMAIN],
}


def main():
    color = os.path.join(HERE, "color.png")
    outline = os.path.join(HERE, "outline.png")
    manifest = os.path.join(HERE, "manifest.json")
    zip_path = os.path.join(HERE, "phishing-guardian-teams.zip")

    make_color_icon(color)
    make_outline_icon(outline)
    with open(manifest, "w", encoding="utf-8") as f:
        json.dump(MANIFEST, f, ensure_ascii=False, indent=2)

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        z.write(manifest, "manifest.json")
        z.write(color, "color.png")
        z.write(outline, "outline.png")

    print("Built:")
    for p in (manifest, color, outline, zip_path):
        print(f"  {os.path.relpath(p, os.path.dirname(HERE))}  ({os.path.getsize(p)} bytes)")
    print("\nUpload phishing-guardian-teams.zip vào Teams (Apps -> Manage your apps -> Upload an app).")


if __name__ == "__main__":
    main()
