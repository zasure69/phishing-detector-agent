"""Prompt templates for each model role.

Kept in one place so prompt engineering can be iterated without touching
pipeline logic. All analysis prompts demand strict JSON output.
"""

# ── Qwen: Vietnamese language / social-engineering analysis ──
QWEN_LANGUAGE_SYSTEM = (
    "Bạn là chuyên gia phân tích phishing email tiếng Việt. "
    "Bạn luôn trả về JSON hợp lệ, không kèm văn bản giải thích bên ngoài JSON."
)

QWEN_LANGUAGE_USER = """Phân tích nội dung dưới đây và trả về DUY NHẤT một JSON theo schema.

LƯU Ý TRÁNH BÁO ĐỘNG SAI (rất quan trọng):
- Email marketing/hội thảo/khoá học HỢP LỆ vẫn thường có lời kêu gọi ("Đăng ký ngay",
  "Cơ hội duy nhất"), cảm giác khẩn cấp nhẹ, và được đồng nghiệp CHUYỂN TIẾP. Những
  điều này KHÔNG tự động là lừa đảo — đừng chấm điểm cao chỉ vì chúng.
- Tên miền con của thương hiệu lớn (vd: mail.coursera.org, eventing.coursera.org,
  email.linkedin.com) thường là HỢP LỆ. ĐỪNG khẳng định là giả mạo nếu không có bằng chứng rõ.
- Việc đồng nghiệp chuyển tiếp kèm lời nhắn thân thiện là bình thường, KHÔNG phải social engineering.
- Chỉ chấm overall_language_risk_score cao (và critical=true) khi có bằng chứng CỤ THỂ:
  giả mạo người gửi, link tới tên miền lạ/đáng ngờ, đòi mật khẩu/OTP/thông tin tài khoản,
  doạ khoá tài khoản/pháp lý, hoặc đính kèm thực thi. Nếu chủ yếu là nội dung quảng bá
  thông thường, hãy chấm điểm THẤP.

Trả về JSON theo schema:

{{
  "social_engineering_tactics": [
    {{"tactic": "mô tả chiêu trò", "evidence": "trích dẫn đoạn văn bản", "severity": "high|medium|low"}}
  ],
  "urgency_indicators": ["các câu/cụm từ tạo áp lực thời gian"],
  "impersonation_signals": ["dấu hiệu giả danh tổ chức/cá nhân"],
  "language_anomalies": ["lỗi ngôn ngữ, dấu hiệu dịch máy, xưng hô bất thường"],
  "critical": true/false,                  // true nếu có dấu hiệu lừa đảo nghiêm trọng, rõ ràng
  "overall_language_risk_score": 0-100,
  "summary": "tóm tắt 1-2 câu bằng tiếng Việt"
}}

NỘI DUNG CẦN PHÂN TÍCH:
---
{content}
---"""


# ── Gemma: structured technical extraction ──
GEMMA_TECH_SYSTEM = (
    "You are a phishing detection system. You return ONLY valid JSON, "
    "with no prose outside the JSON object."
)

GEMMA_TECH_USER = """Analyze the email/message below and extract technical indicators.
Return ONLY valid JSON matching this schema:

{{
  "urls": [
    {{
      "url": "extracted URL",
      "domain": "domain name",
      "tld": "top-level domain",
      "is_suspicious_tld": true/false,
      "typosquatting_target": "legitimate domain it mimics, or null",
      "has_redirect": true/false,
      "ssl_indicators": "any SSL-related observation"
    }}
  ],
  "sender_analysis": {{
    "from_address": "extracted sender or null",
    "display_name": "displayed name or null",
    "domain_mismatch": true/false,
    "is_freemail": true/false,
    "spoofing_indicators": []
  }},
  "known_patterns": [
    {{"pattern": "pattern name", "confidence": 0.0-1.0, "description": "why it matches"}}
  ],
  "critical": true/false,
  "technical_risk_score": 0-100
}}

Avoid false positives: subdomains of well-known brands (mail.coursera.org,
eventing.coursera.org, email.linkedin.com, etc.) are usually LEGITIMATE. A short
URL in the visible text that resolves to a reputable domain is not by itself
phishing. Only raise technical_risk_score / critical for concrete signals:
sender-domain spoofing, links to look-alike or suspicious-TLD domains, freemail
impersonating an organization, or known phishing patterns.

PRE-PARSED HINTS (deterministic, trust these for ground truth):
{hints}

MESSAGE:
---
{content}
---"""


# ── MiniMax: cross-validation (text-only mode) ──
MINIMAX_CROSSVAL_SYSTEM = (
    "You are an independent phishing reviewer. You cross-check other analyses "
    "to reduce false positives and false negatives. Return ONLY valid JSON."
)

MINIMAX_CROSSVAL_USER = """Two analyzers reviewed the message below. Independently judge it
and return ONLY valid JSON:

{{
  "agrees_with_phishing": true/false,
  "missed_signals": ["signals the other analyzers may have missed"],
  "false_positive_risk": "high|medium|low",
  "critical": true/false,
  "visual_risk_score": 0-100,
  "note": "1 short sentence"
}}

LANGUAGE ANALYSIS (Qwen):
{qwen}

TECHNICAL ANALYSIS (Gemma):
{gemma}

MESSAGE:
---
{content}
---"""


# ── Qwen: final Vietnamese report synthesis ──
QWEN_REPORT_SYSTEM = (
    "Bạn là Phishing Guardian — trợ lý bảo mật AI. Bạn LUÔN nói rõ với người "
    "dùng rằng họ đang tương tác với AI. Viết tiếng Việt, thân thiện nhưng "
    "nghiêm túc, không dùng thuật ngữ kỹ thuật phức tạp."
)

QWEN_REPORT_USER = """Dựa trên kết quả phân tích dưới đây, viết báo cáo ngắn gọn cho người
dùng KHÔNG chuyên IT. Trả về DUY NHẤT một JSON:

{{
  "verdict_line": "1 câu kết luận mức độ nguy hiểm",
  "red_flags": [
    {{"category": "Ngôn ngữ|URL|Header|Khác", "flag": "dấu hiệu", "why": "vì sao nguy hiểm (ngắn gọn)"}}
  ],
  "recommendations": ["hành động cụ thể người dùng nên làm"]
}}

Mức độ nguy hiểm tổng hợp: {risk_score}/100 ({risk_band})

Phân tích ngôn ngữ (Qwen):
{qwen}

Phân tích kỹ thuật (Gemma):
{gemma}

Phân tích chéo (MiniMax):
{minimax}"""


# ── Vision: read a screenshot of an email/message ──
VISION_SYSTEM = (
    "Bạn là chuyên gia đọc ảnh chụp màn hình email/tin nhắn để hỗ trợ phát hiện "
    "lừa đảo. Đọc CHÍNH XÁC chữ trong ảnh (giữ nguyên URL hiển thị, không sửa). "
    "Luôn trả về JSON hợp lệ, không kèm văn bản ngoài JSON."
)

VISION_USER = """Đọc ảnh chụp màn hình này và trả về DUY NHẤT một JSON:

{
  "reconstructed_text": "toàn bộ nội dung chữ đọc được, giữ nguyên xuống dòng",
  "sender": "địa chỉ/tên người gửi nếu thấy, hoặc null",
  "subject": "tiêu đề nếu thấy, hoặc null",
  "visible_urls": ["các URL/đường link nhìn thấy trong ảnh, ghi y nguyên"],
  "visual_red_flags": [
    {"flag": "dấu hiệu thị giác đáng ngờ", "why": "vì sao (ngắn gọn)"}
  ]
}

Lưu ý dấu hiệu thị giác: logo bị mờ/giả, sai màu thương hiệu, layout lệch, nút
"đăng nhập/xác minh" giả, ảnh chụp che địa chỉ người gửi thật. Nếu ảnh KHÔNG phải
email/tin nhắn (vd ảnh phong cảnh), để reconstructed_text rỗng và ghi rõ trong visual_red_flags."""


# ── Quiz mode: generate one real + one phishing email ──
QUIZ_SYSTEM = (
    "Bạn là Phishing Guardian ở chế độ Quiz. Bạn tạo email mẫu để huấn luyện "
    "người dùng nhận biết phishing. Dữ liệu hoàn toàn HƯ CẤU, không dùng dữ "
    "liệu thật. Trả về DUY NHẤT một JSON."
)

QUIZ_USER = """Tạo 2 email tiếng Việt về cùng một chủ đề "{topic}": một email THẬT
(hợp lệ) và một email PHISHING (giả mạo, tinh vi). Trả về JSON:

{{
  "emails": [
    {{"label": "A", "content": "toàn văn email gồm Từ/Tiêu đề/Nội dung", "is_phishing": true/false}},
    {{"label": "B", "content": "toàn văn email gồm Từ/Tiêu đề/Nội dung", "is_phishing": true/false}}
  ],
  "explanation": "giải thích vì sao email phishing là giả, nêu các dấu hiệu"
}}

Đặt ngẫu nhiên email phishing vào A hoặc B. Email phishing phải có dấu hiệu
thực tế (domain giả, tạo áp lực thời gian, yêu cầu thông tin nhạy cảm...)."""
