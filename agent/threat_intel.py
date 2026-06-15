"""VirusTotal enrichment — ground-truth reputation, privacy-safe.

Design constraints (see project evaluation):
  • URLs/domains: REPUTATION lookups only (GET /domains/{d}) — never submit-and-poll.
  • Files: SHA-256 HASH lookups only (GET /files/{hash}) — NEVER upload bytes.
    Only the hash leaves the box, so no confidential content is shared with VT.
  • Best-effort: any error / missing key / rate-limit → returns empty, pipeline
    runs unaffected. A positive detection forces a critical verdict; "unknown"
    NEVER lowers vigilance.

Free public API is 4 req/min, 500/day — so we cap domain lookups and cache.
"""
from __future__ import annotations

from typing import Any

import requests

from . import config
from .eml_parser import SHORTENERS, _wrapper_name

_BASE = "https://www.virustotal.com/api/v3"
_cache: dict[str, dict | None] = {}


def _get(path: str) -> dict | None:
    """GET a VT v3 endpoint. Returns parsed JSON, or None on any failure."""
    try:
        resp = requests.get(
            f"{_BASE}{path}",
            headers={"x-apikey": config.VT_API_KEY},
            timeout=config.VT_TIMEOUT_SECONDS,
        )
    except requests.RequestException:
        return None
    if resp.status_code == 404:
        return {"_not_found": True}
    if resp.status_code != 200:
        return None  # 401 bad key, 429 rate-limited, etc. → degrade silently
    try:
        return resp.json()
    except ValueError:
        return None


def _stats(data: dict) -> dict[str, int]:
    s = (data.get("data", {}).get("attributes", {})
         .get("last_analysis_stats", {}) or {})
    malicious = int(s.get("malicious", 0))
    suspicious = int(s.get("suspicious", 0))
    total = sum(int(v) for v in s.values()) or 0
    return {"malicious": malicious, "suspicious": suspicious, "total": total}


def domain_reputation(domain: str) -> dict | None:
    key = f"d:{domain}"
    if key in _cache:
        return _cache[key]
    data = _get(f"/domains/{domain}")
    result = None if not data or data.get("_not_found") else _stats(data)
    _cache[key] = result
    return result


def file_reputation(sha256: str) -> dict | None:
    key = f"f:{sha256}"
    if key in _cache:
        return _cache[key]
    data = _get(f"/files/{sha256}")
    if not data:
        result = None
    elif data.get("_not_found"):
        result = {"known": False}
    else:
        result = {"known": True, **_stats(data)}
    _cache[key] = result
    return result


def _candidate_domains(parsed) -> list[str]:
    """Distinct real destination domains worth checking (skip wrappers/shorteners)."""
    out: list[str] = []
    seen: set[str] = set()
    for u in parsed.urls:
        d = (u.domain or "").lower()
        if not d or d in seen:
            continue
        if _wrapper_name(d) or d in SHORTENERS:
            continue
        seen.add(d)
        out.append(d)
    return out[: config.VT_MAX_DOMAINS]


def enrich(parsed) -> tuple[list[dict], bool, dict[str, Any]]:
    """Return (deterministic flags, force_critical, summary).

    Safe to call unconditionally — no-ops when VT is not configured.
    """
    if not config.vt_configured():
        return [], False, {"enabled": False}

    flags: list[dict] = []
    critical = False
    summary: dict[str, Any] = {"enabled": True, "domains": [], "files": []}

    for d in _candidate_domains(parsed):
        rep = domain_reputation(d)
        if rep is None:
            continue
        summary["domains"].append({"domain": d, **rep})
        if rep["malicious"] > 0:
            critical = True
            flags.append({
                "category": "VirusTotal",
                "flag": f"{rep['malicious']}/{rep['total']} công cụ bảo mật đánh giá '{d}' là ĐỘC HẠI",
                "why": "Tên miền nằm trong danh sách đen của các hãng bảo mật — nguy cơ phishing/mã độc cao",
            })
        elif rep["suspicious"] >= 2:
            flags.append({
                "category": "VirusTotal",
                "flag": f"{rep['suspicious']} công cụ bảo mật cảnh báo '{d}' đáng ngờ",
                "why": "Một số hãng bảo mật đánh dấu tên miền này là đáng ngờ",
            })

    for a in parsed.attachments:
        h = a.get("sha256")
        if not h:
            continue
        rep = file_reputation(h)
        if rep is None or not rep.get("known"):
            continue
        summary["files"].append({"filename": a["filename"], **rep})
        if rep.get("malicious", 0) > 0:
            critical = True
            flags.append({
                "category": "VirusTotal",
                "flag": f"Tệp '{a['filename']}': {rep['malicious']}/{rep['total']} antivirus phát hiện MÃ ĐỘC",
                "why": "File trùng khớp mẫu mã độc đã biết trên VirusTotal",
            })

    return flags, critical, summary
