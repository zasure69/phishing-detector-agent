"""Parse uploaded email files (.eml / .msg / .html) into a rich ParsedInput.

Pasting text into chat loses the two strongest phishing signals: the real
hyperlink targets (HTML `<a href>` differs from the visible text) and the
true headers / attachments. Parsing the original file recovers them.

Supported:
  .eml / .mime / .txt  → stdlib `email` (RFC 822)
  .html / .htm         → HTML body only (link + text extraction)
  .msg                 → Outlook, via optional `extract_msg` dependency
"""
from __future__ import annotations

import io
import re
from email import message_from_bytes
from email.policy import default as default_policy
from email.utils import getaddresses, parseaddr
from html.parser import HTMLParser
from urllib.parse import parse_qs, unquote, urlparse

from .parser import (
    FREEMAIL_DOMAINS,
    SUSPICIOUS_TLDS,
    ParsedInput,
    ParsedUrl,
    _domain_of,
    _tld_of,
    extract_urls,
)

# Attachment extensions that are dangerous to open.
EXEC_EXT = {
    "exe", "scr", "com", "bat", "cmd", "pif", "js", "jse", "vbs", "vbe",
    "wsf", "wsh", "hta", "jar", "ps1", "msi", "msc", "cpl", "lnk", "reg",
    "iso", "img", "vhd",
}
SCRIPT_DOC_EXT = {"docm", "xlsm", "pptm", "dotm", "xlam", "xlsb"}
HTML_EXT = {"html", "htm", "shtml"}
ARCHIVE_EXT = {"zip", "rar", "7z", "gz", "ace", "cab"}
_DOUBLE_EXT_RE = re.compile(r"\.[a-z0-9]{2,4}\.(" + "|".join(EXEC_EXT) + r")$", re.I)

# URL shorteners hide the real destination — a phishing signal on their own.
SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rb.gy", "shorturl.at", "t.ly", "rebrand.ly", "tiny.cc",
    "bit.do", "soo.gd", "s.id", "shorte.st", "v.gd", "lnkd.in",
}


def _wrapper_name(host: str) -> str | None:
    """Identify a legitimate corporate URL-protection wrapper from its host."""
    if host.endswith("safelinks.protection.outlook.com"):
        return "Microsoft Safe Links"
    if "urldefense.proofpoint.com" in host or host.endswith("urldefense.com"):
        return "Proofpoint URLDefense"
    if "protect.mimecast.com" in host:
        return "Mimecast"
    if host.endswith("clicktime.symantec.com") or "safeweb.norton.com" in host:
        return "Symantec ClickTime"
    return None


def unwrap_url(url: str, depth: int = 0) -> str:
    """Recover the real destination from a corporate URL-protection wrapper.

    Outlook Safe Links / Proofpoint / Mimecast rewrite every link in an email
    so the visible href becomes the wrapper's domain. Comparing against that
    wrapper would flag every link as a fake mismatch — so we must unwrap first.
    """
    if not url or depth > 4:
        return url
    try:
        host = _domain_of(url)
        if host.endswith("safelinks.protection.outlook.com"):
            real = (parse_qs(urlparse(url).query).get("url") or [None])[0]
            if real:
                return unwrap_url(unquote(real), depth + 1)
        if "urldefense.proofpoint.com" in host:  # Proofpoint v2
            u = (parse_qs(urlparse(url).query).get("u") or [None])[0]
            if u:
                return unwrap_url(unquote(u.replace("-", "%").replace("_", "/")), depth + 1)
        if host.endswith("urldefense.com"):  # Proofpoint v3
            m = re.search(r"/v3/__(.+?)__(?:;|$)", url)
            if m:
                return unwrap_url(unquote(m.group(1)), depth + 1)
        # Mimecast / Symantec embed an opaque token, not the original URL — leave as-is.
    except Exception:
        pass
    return url


class _HtmlExtract(HTMLParser):
    """Collect <a href> links (with their visible text) and stripped text."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str]] = []
        self._href: str | None = None
        self._atext: list[str] = []
        self._text: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip += 1
        if tag == "a":
            d = dict(attrs)
            self._href = d.get("href")
            self._atext = []

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1
        if tag == "a" and self._href is not None:
            self.links.append(("".join(self._atext).strip(), self._href))
            self._href = None

    def handle_data(self, data):
        if self._skip:
            return
        if self._href is not None:
            self._atext.append(data)
        self._text.append(data)

    @property
    def text(self) -> str:
        return re.sub(r"[ \t]*\n[ \t]*", "\n", " ".join(self._text)).strip()


def _ext_of(filename: str) -> str:
    return filename.rsplit(".", 1)[-1].lower() if "." in filename else ""


def _attachment_risk(filename: str, content_type: str) -> tuple[bool, str]:
    ext = _ext_of(filename)
    if _DOUBLE_EXT_RE.search(filename):
        return True, "Đuôi file giả mạo kép (vd: .pdf.exe) — dấu hiệu mã độc rõ ràng"
    if ext in EXEC_EXT:
        return True, f"Đuôi '.{ext}' là file thực thi — tuyệt đối không mở"
    if ext in SCRIPT_DOC_EXT:
        return True, f"Tài liệu '.{ext}' có thể chứa macro độc hại"
    if ext in HTML_EXT:
        return True, "File HTML đính kèm thường là trang đăng nhập giả"
    if ext in ARCHIVE_EXT:
        return False, f"File nén '.{ext}' — có thể giấu mã độc bên trong, thận trọng"
    return False, ""


def _domains_related(a: str, b: str) -> bool:
    """True when two domains are the same or one is a subdomain of the other."""
    return a == b or a.endswith("." + b) or b.endswith("." + a)


def _analyze_links(links: list[tuple[str, str]]) -> tuple[list[dict], list[dict], bool]:
    """Return (link records, deterministic flags, critical?).

    Links are unwrapped from corporate protection wrappers (Safe Links etc.)
    BEFORE any comparison, so the wrapper domain is never mistaken for a
    mismatch. The visible text is compared against the real destination.
    """
    records: list[dict] = []
    flags: list[dict] = []
    critical = False
    seen_mismatch: set[str] = set()
    shortener_seen: set[str] = set()
    susp_seen: set[str] = set()
    for text, href in links:
        if not href or href.startswith(("mailto:", "tel:", "#")):
            continue
        wrapper = _wrapper_name(_domain_of(href))
        real = unwrap_url(href)
        href_domain = _domain_of(real)
        # If the visible text itself looks like a URL/domain, compare domains.
        text_domain = ""
        m = re.search(r"[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", text or "")
        if m:
            text_domain = _domain_of(m.group(0))
        # A wrapper we could not unwrap (e.g. Mimecast token) is NOT a mismatch.
        still_wrapped = bool(_wrapper_name(href_domain))
        mismatch = bool(
            text_domain and href_domain and not still_wrapped
            and not _domains_related(text_domain, href_domain)
        )
        records.append({
            "text": (text or "")[:120],
            "href": real[:300],
            "original_href": href[:300] if wrapper else None,
            "wrapper": wrapper,
            "href_domain": href_domain,
            "text_domain": text_domain,
            "mismatch": mismatch,
        })
        key = f"{text_domain}->{href_domain}"
        if mismatch and key not in seen_mismatch:
            seen_mismatch.add(key)
            critical = True
            flags.append({
                "category": "URL",
                "flag": f"Link hiển thị '{text_domain}' nhưng thực tế dẫn tới '{href_domain}'",
                "why": "Kẻ lừa đảo ngụy trang link thật bằng tên miền quen thuộc — dấu hiệu phishing kinh điển",
            })
        if href_domain in SHORTENERS and href_domain not in shortener_seen:
            shortener_seen.add(href_domain)
            flags.append({
                "category": "URL",
                "flag": f"Dùng link rút gọn ({href_domain}) che giấu đích đến thật",
                "why": "Link rút gọn ẩn URL thật — không thể biết trang/file đích trước khi bấm",
            })
        tld = _tld_of(href_domain)
        if tld in SUSPICIOUS_TLDS and href_domain not in susp_seen:
            susp_seen.add(href_domain)
            flags.append({
                "category": "URL",
                "flag": f"Tên miền đáng ngờ: {href_domain}",
                "why": f"TLD '.{tld}' thường bị lạm dụng cho phishing",
            })
    return records, flags, critical


def _normalized_content(p: ParsedInput, body_text: str) -> str:
    """Build a normalized text representation that exposes ALL signals to the LLMs."""
    lines = []
    if p.sender:
        lines.append(f"Từ (From): {p.sender}")
    if p.reply_to and p.reply_to != p.sender:
        lines.append(f"Reply-To: {p.reply_to}")
    if p.return_path:
        lines.append(f"Return-Path: {p.return_path}")
    if p.recipient:
        lines.append(f"Đến (To): {p.recipient}")
    if p.subject:
        lines.append(f"Tiêu đề (Subject): {p.subject}")
    if p.auth_results:
        lines.append(f"Authentication-Results: {p.auth_results}")
    lines.append("")
    lines.append("[NỘI DUNG EMAIL]")
    lines.append(body_text.strip() or "(trống)")
    real_links = [l for l in p.links if l["href_domain"]]
    if real_links:
        lines.append("")
        lines.append("[LIÊN KẾT THỰC SỰ TRONG EMAIL]")
        if any(l.get("wrapper") for l in real_links):
            lines.append("(Lưu ý: các link đã được hệ thống bảo mật của tổ chức bọc lại — "
                         "đây là việc HỢP LỆ, KHÔNG phải dấu hiệu lừa đảo. URL bên dưới là đích THẬT đã được giải mã.)")
        for l in real_links[:20]:
            tag = "  ⚠️ KHÁC TÊN MIỀN" if l["mismatch"] else ""
            disp = f'"{l["text"]}" → ' if l["text"] else ""
            lines.append(f"- {disp}{l['href']}{tag}")
    if p.attachments:
        lines.append("")
        lines.append("[TỆP ĐÍNH KÈM]")
        for a in p.attachments:
            warn = f"  ⚠️ {a['reason']}" if a.get("reason") else ""
            kb = f"{round(a['size']/1024)}KB" if a.get("size") else "?"
            lines.append(f"- {a['filename']} ({a['content_type']}, {kb}){warn}")
    return "\n".join(lines)


def _finalize(p: ParsedInput, body_text: str) -> ParsedInput:
    """Compute deterministic flags, merge links→urls, build normalized content."""
    flags = list(p.deterministic_flags)
    critical = p.deterministic_critical

    # Links → deterministic URL findings + populate p.urls with REAL hrefs.
    link_records, link_flags, link_critical = _analyze_links(
        [(l["text"], l["href"]) for l in p.links] if p.links else []
    )
    if link_records:
        p.links = link_records
    flags.extend(link_flags)
    critical = critical or link_critical

    # Merge href URLs into urls (for Gemma hints), plus any URLs found in text.
    url_seen = {u.raw for u in p.urls}
    for l in p.links:
        if l["href"] and l["href"] not in url_seen and l["href"].startswith("http"):
            url_seen.add(l["href"])
            dom = l["href_domain"]
            tld = _tld_of(dom)
            p.urls.append(ParsedUrl(raw=l["href"], domain=dom, tld=tld,
                                    suspicious_tld=tld in SUSPICIOUS_TLDS))
    for u in extract_urls(body_text):
        if u.raw not in url_seen:
            url_seen.add(u.raw)
            p.urls.append(u)

    # Attachment findings.
    for a in p.attachments:
        if a.get("suspicious"):
            critical = True
            flags.append({"category": "Đính kèm", "flag": f"Tệp nguy hiểm: {a['filename']}",
                          "why": a.get("reason", "")})
        elif a.get("reason"):
            flags.append({"category": "Đính kèm", "flag": f"Tệp cần thận trọng: {a['filename']}",
                          "why": a.get("reason", "")})

    # Header anomalies.
    if p.reply_to:
        rd = _domain_of(parseaddr(p.reply_to)[1] or p.reply_to)
        if p.sender_domain and rd and rd != p.sender_domain:
            flags.append({"category": "Header", "flag": f"Reply-To khác domain người gửi ({rd} ≠ {p.sender_domain})",
                          "why": "Trả lời sẽ đi tới địa chỉ của kẻ tấn công, không phải người gửi hiển thị"})
    if p.is_freemail and p.sender_domain:
        flags.append({"category": "Header", "flag": f"Gửi từ email cá nhân ({p.sender_domain})",
                      "why": "Tổ chức thật hiếm khi dùng email miễn phí cho thông báo chính thức"})
    if p.auth_results and re.search(r"(spf|dkim|dmarc)=fail", p.auth_results, re.I):
        critical = True
        flags.append({"category": "Header", "flag": "Xác thực email thất bại (SPF/DKIM/DMARC fail)",
                      "why": "Email nhiều khả năng bị giả mạo địa chỉ người gửi (spoofing)"})

    p.deterministic_flags = flags
    p.deterministic_critical = critical
    body_norm = _normalized_content(p, body_text)
    p.body = body_norm
    p.raw = body_norm
    return p


def _decode_part(part) -> str:
    try:
        return part.get_content()
    except Exception:
        payload = part.get_payload(decode=True)
        if payload is None:
            return ""
        charset = part.get_content_charset() or "utf-8"
        try:
            return payload.decode(charset, errors="replace")
        except Exception:
            return payload.decode("utf-8", errors="replace")


def parse_eml(raw: bytes, filename: str | None = None) -> ParsedInput:
    msg = message_from_bytes(raw, policy=default_policy)

    sender = str(msg.get("From", "") or "").strip()
    name, addr = parseaddr(sender)
    p = ParsedInput(input_type="eml", raw="", source_filename=filename)
    p.sender = sender or None
    p.sender_email = addr.lower() or None
    p.sender_domain = addr.split("@")[-1].lower() if "@" in addr else None
    p.is_freemail = p.sender_domain in FREEMAIL_DOMAINS if p.sender_domain else False
    p.subject = str(msg.get("Subject", "") or "").strip() or None
    p.recipient = ", ".join(a for _, a in getaddresses(msg.get_all("To", []))) or None
    p.reply_to = str(msg.get("Reply-To", "") or "").strip() or None
    p.return_path = str(msg.get("Return-Path", "") or "").strip() or None
    p.auth_results = str(msg.get("Authentication-Results", "") or "").strip() or None
    p.received_count = len(msg.get_all("Received", []))

    text_body, html_body = "", ""
    for part in msg.walk():
        if part.is_multipart():
            continue
        disp = (part.get_content_disposition() or "").lower()
        ctype = part.get_content_type()
        fname = part.get_filename()
        if disp == "attachment" or fname:
            payload = part.get_payload(decode=True) or b""
            susp, reason = _attachment_risk(fname or "", ctype)
            p.attachments.append({
                "filename": fname or "(no name)", "content_type": ctype,
                "size": len(payload), "ext": _ext_of(fname or ""),
                "suspicious": susp, "reason": reason,
            })
        elif ctype == "text/plain":
            text_body += _decode_part(part) + "\n"
        elif ctype == "text/html":
            html_body += _decode_part(part)

    if html_body:
        h = _HtmlExtract()
        h.feed(html_body)
        p.links = [{"text": t, "href": hr} for t, hr in h.links]
        body_text = text_body.strip() or h.text
    else:
        body_text = text_body.strip()

    return _finalize(p, body_text)


def parse_html(raw: bytes, filename: str | None = None) -> ParsedInput:
    html = raw.decode("utf-8", errors="replace")
    h = _HtmlExtract()
    h.feed(html)
    p = ParsedInput(input_type="html", raw="", source_filename=filename)
    p.links = [{"text": t, "href": hr} for t, hr in h.links]
    return _finalize(p, h.text)


def parse_msg(raw: bytes, filename: str | None = None) -> ParsedInput:
    try:
        import extract_msg  # optional dependency
    except ImportError:
        raise ValueError(
            "File .msg cần thư viện 'extract-msg'. Hãy export email sang .eml, "
            "hoặc cài extract-msg và deploy lại."
        )
    m = extract_msg.openMsg(io.BytesIO(raw))
    p = ParsedInput(input_type="msg", raw="", source_filename=filename)
    sender = (m.sender or "").strip()
    name, addr = parseaddr(sender)
    p.sender = sender or None
    p.sender_email = addr.lower() or None
    p.sender_domain = addr.split("@")[-1].lower() if "@" in addr else None
    p.is_freemail = p.sender_domain in FREEMAIL_DOMAINS if p.sender_domain else False
    p.subject = (m.subject or "").strip() or None
    p.recipient = (m.to or "").strip() or None
    body_text = (m.body or "").strip()
    html_body = m.htmlBody or b""
    if isinstance(html_body, bytes):
        html_body = html_body.decode("utf-8", errors="replace")
    if html_body:
        h = _HtmlExtract()
        h.feed(html_body)
        p.links = [{"text": t, "href": hr} for t, hr in h.links]
        body_text = body_text or h.text
    for att in getattr(m, "attachments", []) or []:
        fname = getattr(att, "longFilename", None) or getattr(att, "shortFilename", "") or ""
        data = getattr(att, "data", b"") or b""
        size = len(data) if isinstance(data, (bytes, bytearray)) else 0
        susp, reason = _attachment_risk(fname, "application/octet-stream")
        p.attachments.append({
            "filename": fname or "(no name)", "content_type": "application/octet-stream",
            "size": size, "ext": _ext_of(fname), "suspicious": susp, "reason": reason,
        })
    return _finalize(p, body_text)


def parse_file(raw: bytes, filename: str | None) -> ParsedInput:
    """Dispatch by extension. Falls back to plain-text parsing."""
    ext = _ext_of(filename or "")
    if ext == "msg":
        return parse_msg(raw, filename)
    if ext in ("html", "htm", "shtml"):
        return parse_html(raw, filename)
    if ext in ("eml", "mime", "") or ext == "txt":
        text = raw.decode("utf-8", errors="replace")
        # Heuristic: looks like a raw MIME message → full EML parse.
        if re.search(r"^(from|subject|to|received|content-type)\s*:", text[:2000], re.I | re.M):
            return parse_eml(raw, filename)
        from .parser import parse as parse_text
        return parse_text(text)
    # Unknown binary → try EML, else plain text.
    try:
        return parse_eml(raw, filename)
    except Exception:
        from .parser import parse as parse_text
        return parse_text(raw.decode("utf-8", errors="replace"))
