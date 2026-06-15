"""Deterministic input parsing & classification.

Splits raw user input into structured parts (sender, subject, body, URLs)
before any LLM sees it. Doing this in plain Python keeps the technical
signals reliable and gives the models cleaner context.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# Common free email providers — a corporate sender on these is a red flag.
FREEMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "yahoo.com.vn", "hotmail.com", "outlook.com",
    "icloud.com", "proton.me", "protonmail.com", "live.com", "aol.com",
}

# TLDs frequently abused for phishing / throwaway domains.
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "buzz", "click", "link",
    "work", "country", "kim", "loan", "men", "online", "site", "click",
}

URL_RE = re.compile(r"""(?xi)\b((?:https?://|www\.)[^\s<>"'\)\]]+)""")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")

# Header line patterns — tolerant of Vietnamese and English label variants.
_FROM_RE = re.compile(r"^(?:from|từ|sender|người gửi)\s*:\s*(.+)$", re.I | re.M)
_SUBJ_RE = re.compile(r"^(?:subject|tiêu đề|chủ đề)\s*:\s*(.+)$", re.I | re.M)
_TO_RE = re.compile(r"^(?:to|đến|gửi tới)\s*:\s*(.+)$", re.I | re.M)


@dataclass
class ParsedUrl:
    raw: str
    domain: str
    tld: str
    suspicious_tld: bool


@dataclass
class ParsedInput:
    input_type: str                       # "email" | "url" | "text" | "eml" | "msg" | "html"
    raw: str
    sender: str | None = None
    sender_email: str | None = None
    sender_domain: str | None = None
    is_freemail: bool = False
    subject: str | None = None
    recipient: str | None = None
    body: str = ""
    urls: list[ParsedUrl] = field(default_factory=list)
    # Rich fields populated only from uploaded files (EML/MSG/HTML).
    reply_to: str | None = None
    return_path: str | None = None
    auth_results: str | None = None
    received_count: int = 0
    links: list[dict] = field(default_factory=list)        # {text, href, href_domain, text_domain, mismatch}
    attachments: list[dict] = field(default_factory=list)  # {filename, content_type, size, ext, suspicious, reason}
    source_filename: str | None = None
    # Deterministic findings detected before/independent of the LLMs.
    deterministic_critical: bool = False
    deterministic_flags: list[dict] = field(default_factory=list)  # {category, flag, why}

    def to_dict(self) -> dict:
        return {
            "input_type": self.input_type,
            "sender": self.sender,
            "sender_email": self.sender_email,
            "sender_domain": self.sender_domain,
            "is_freemail": self.is_freemail,
            "subject": self.subject,
            "recipient": self.recipient,
            "reply_to": self.reply_to,
            "return_path": self.return_path,
            "auth_results": self.auth_results,
            "received_count": self.received_count,
            "urls": [u.__dict__ for u in self.urls],
            "links": self.links,
            "attachments": self.attachments,
            "source_filename": self.source_filename,
            "deterministic_critical": self.deterministic_critical,
            "body": self.body,
        }


def _domain_of(url: str) -> str:
    host = re.sub(r"^https?://", "", url, flags=re.I)
    host = host.split("/")[0].split("?")[0].split("@")[-1]
    host = host.split(":")[0]
    return host.lower().lstrip(".")


def _tld_of(domain: str) -> str:
    parts = domain.split(".")
    return parts[-1] if len(parts) > 1 else ""


def extract_urls(text: str) -> list[ParsedUrl]:
    seen: set[str] = set()
    out: list[ParsedUrl] = []
    for m in URL_RE.finditer(text):
        raw = m.group(1).rstrip(".,);]")
        if raw in seen:
            continue
        seen.add(raw)
        domain = _domain_of(raw)
        tld = _tld_of(domain)
        out.append(
            ParsedUrl(raw=raw, domain=domain, tld=tld,
                      suspicious_tld=tld in SUSPICIOUS_TLDS)
        )
    return out


def _classify(text: str, has_headers: bool) -> str:
    stripped = text.strip()
    if has_headers:
        return "email"
    # Single URL (optionally with a little surrounding text) → url check.
    urls = URL_RE.findall(stripped)
    if urls and len(stripped) < 200 and len(urls) <= 2:
        no_url = URL_RE.sub("", stripped).strip()
        if len(no_url) < 40:
            return "url"
    return "text"


def parse(raw: str) -> ParsedInput:
    """Parse arbitrary pasted content into a structured ParsedInput."""
    text = (raw or "").strip()

    from_m = _FROM_RE.search(text)
    subj_m = _SUBJ_RE.search(text)
    to_m = _TO_RE.search(text)
    has_headers = bool(from_m or subj_m)

    input_type = _classify(text, has_headers)

    parsed = ParsedInput(input_type=input_type, raw=text, body=text)

    if from_m:
        sender_line = from_m.group(1).strip()
        parsed.sender = sender_line
        em = EMAIL_RE.search(sender_line)
        if em:
            parsed.sender_email = em.group(0).lower()
            parsed.sender_domain = parsed.sender_email.split("@")[-1]
            parsed.is_freemail = parsed.sender_domain in FREEMAIL_DOMAINS
    if subj_m:
        parsed.subject = subj_m.group(1).strip()
    if to_m:
        parsed.recipient = to_m.group(1).strip()

    parsed.urls = extract_urls(text)
    return parsed
