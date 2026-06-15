# Phishing Guardian — Claw-a-thon 2026 Project Brief

## Bối cảnh cuộc thi

- **Cuộc thi**: Claw-a-thon 2026 — Internal AI Hackathon của VNG Group, tổ chức bởi GreenNode
- **Hạn nộp**: 17/06/2026 12:00
- **Voting**: 22/06 → 03/07/2026 — TOÀN BỘ nhân viên VNG Group bình chọn (không phải ban giám khảo kỹ thuật)
- **Track**: Agentic Assistant · **Platform bắt buộc**: AgentBase (trên GreenNode)
- **Rulebook**: https://greennode.ai/claw-a-thon-rulebook

## Tài nguyên được cấp

- 3 OpenClaw instances (2 vCPU / 4GB RAM mỗi instance)
- POC Wallet 10,000,000 VND cho GreenNode services
- MaaS API tokens cho Qwen, Gemma (pre-opened self-hosted) + MiniMax M2.5

## Yêu cầu submission

1. **Agent chạy trên AgentBase** — BTC phải gọi được ít nhất 1 request thành công
2. **Demo video 2-3 phút** (YouTube hoặc OneDrive VNG) — chạy end-to-end 1 use case
3. **README + mô tả ≤300 từ** — nêu rõ: problem, user, solution, value
4. **AgentBase project link (GitHub)** — public hoặc internal repo

---

## Ý tưởng: Phishing Guardian

Agent AI phát hiện email/tin nhắn lừa đảo phishing, đặc biệt tối ưu cho tiếng Việt.
**Mọi nhân viên** có thể dùng qua một **giao diện chat web** đơn giản: dán email / URL /
tin nhắn đáng ngờ vào ô chat → agent trả về mức độ rủi ro + giải thích + khuyến nghị.

### Pain point
Nhân viên VNG (và mọi công ty tech) liên tục nhận email/tin nhắn lừa đảo. Nhiều người
không chắc cái nào thật, cái nào giả — đặc biệt phishing tiếng Việt ngày càng tinh vi
(giả danh HR, IT, ngân hàng). Họ cần một nơi **dễ truy cập, không cần cài đặt** để hỏi
nhanh "cái này có phải lừa đảo không?".

### Giải pháp
Một **web chatbot** (mở bằng link, không cần đăng nhập/cài app) phục vụ người dùng phổ
thông. Người dùng dán nội dung **hoặc tải lên file email (.eml/.msg/.html)** → Agent phân
tích đa chiều qua 3 model AI → trả về risk level + giải thích chi tiết TẠI SAO đáng ngờ +
khuyến nghị hành động, bằng tiếng Việt dễ hiểu cho người KHÔNG chuyên IT.

> **Vì sao cần upload file?** Copy-paste làm mất 2 tín hiệu phishing mạnh nhất: (1) URL
> thật ẩn sau text (email HTML hiển thị "vietcombank.com.vn" nhưng `href` thật là
> `vcb-secure.tk`), và (2) header thật + file đính kèm. Upload `.eml/.msg` khôi phục đầy
> đủ. Khi đó agent phát hiện thêm (deterministic, không cần LLM): **mismatch chữ hiển thị
> ↔ link thật**, **đính kèm nguy hiểm** (.exe, đuôi kép .pdf.exe, macro), **Reply-To khác
> domain**, **SPF/DKIM/DMARC fail** — mỗi cái có thể tự đẩy verdict lên NGUY HIỂM.
>
> **Quan trọng — Safe Links unwrapping**: Outlook (và Proofpoint/Mimecast) viết lại MỌI URL
> thành link bọc (`apc01.safelinks.protection.outlook.com/?url=...`). Phải **giải mã** lấy URL
> thật TRƯỚC khi so sánh, nếu không sẽ báo nhầm mọi link là "mismatch". `unwrap_url()` trong
> `eml_parser.py` xử lý việc này; bản thân việc bọc link là HỢP LỆ, không phải dấu hiệu lừa đảo.

### Vì sao idea này sẽ thắng vote
- Pain point toàn công ty (không chỉ team security) — kế toán, HR, marketing, dev đều nhận email lạ
- Giao diện chat **ai cũng dùng được ngay**, demo trực quan trên màn hình
- Agent "bóc trần" từng thủ đoạn phishing tiếng Việt tinh vi
- Có **Quiz Mode** để gamify, tăng tính tương tác khi demo

---

## Kiến trúc kỹ thuật

### Giao diện người dùng — Web Chat Widget
Agent **tự phục vụ trang chat** ngay trên runtime (cùng origin với API → không vướng
CORS). Người dùng chỉ cần mở URL endpoint trên trình duyệt.

- `GET /` (và `/chat`) → trang chat HTML (`web/index.html`)
- `POST /invocations` → API phân tích (trang chat gọi vào đây)
- `GET /health` → health check cho AgentBase

```
Trình duyệt người dùng
   │  mở link endpoint → trang chat (web/index.html)
   │  dán email / URL / text → fetch POST /invocations
   ▼
Phishing Guardian Agent (AgentBase Custom Runtime, port 8080)
   │  parser.py — tách sender / subject / body / URLs (deterministic, no LLM)
   ▼
┌─────────────────┬──────────────────────┬─────────────────────┐
│  Qwen 3.5 27B   │  Gemma 4 31B-IT      │  MiniMax M2.5       │
│  ngôn ngữ VN    │  structured JSON     │  cross-validation   │
│ • social eng.   │ • URL/domain analysis│ • soát lại Q+G      │
│ • urgency       │ • header anomalies   │ • giảm false pos.   │
│ • impersonation │ • pattern matching   │ • (vision nếu có)   │
└────────┬────────┴──────────┬───────────┴──────────┬──────────┘
         ▼ (Qwen ‖ Gemma song song)                  ▼
              Risk Scoring Engine (weighted 40/35/25)
              + critical-flag floor (≥71 → NGUY HIỂM)
                              ▼
              Qwen 3.5 — tổng hợp báo cáo tiếng Việt
                              ▼
   🟢 AN TOÀN (0-30) · 🟡 NGHI NGỜ (31-70) · 🔴 NGUY HIỂM (71-100)
```

### Vai trò từng model

| Model | `path` (MaaS) | Vai trò |
|-------|---------------|---------|
| **Qwen 3.5 27B** | `qwen/qwen3-5-27b` | Phân tích ngôn ngữ VN (social engineering, urgency, impersonation, dấu hiệu dịch máy) **+ tổng hợp báo cáo cuối** |
| **Gemma 4 31B-IT** | `google/gemma-4-31b-it` | Structured JSON: URL/domain/typosquatting, header mismatch, pattern matching, confidence scores |
| **MiniMax M2.5** | `minimax/minimax-m2.5` | Cross-validation kết quả Qwen+Gemma để giảm false positive (vision nếu hỗ trợ screenshot) |

> **Gotcha quan trọng**: Qwen 3.5 là reasoning model — nếu không tắt "thinking" nó sẽ
> tiêu hết token budget cho phần suy luận ẩn và trả về `content` rỗng. Bắt buộc gửi
> `extra_body={"chat_template_kwargs":{"enable_thinking":false}}` (cả 3 model đều chấp
> nhận, nhanh hơn ~20×). Điều khiển bằng `DISABLE_THINKING=true` trong `.env`.

### Risk Scoring Engine
- Weighted average: `language 0.40` (Qwen) + `technical 0.35` (Gemma) + `visual 0.25` (MiniMax)
- Nếu MiniMax bị tắt/skip → 0.25 được phân bổ lại cho Qwen+Gemma (không kéo điểm về 0)
- Nếu BẤT KỲ model nào gắn cờ `critical` → final score sàn ở **71** (vào dải NGUY HIỂM)
- Mọi analyzer **degrade gracefully**: lỗi 1 model không làm sập pipeline

### Output cho người dùng
Risk gauge (thanh màu) + điểm /100 + 1 câu kết luận + danh sách dấu hiệu (kèm category &
lý do) + khuyến nghị hành động + tuyên bố rõ "đang tương tác với AI".

### Cấu trúc code

| File | Vai trò |
|------|---------|
| `main.py` | AgentBase entrypoint — phục vụ web UI (`GET /`), API (`POST /invocations`), `GET /health` |
| `web/index.html` | Giao diện chat web + upload file/drag-drop (self-contained, không CDN ngoài) |
| `agent/config.py` | Config từ env (model paths, weights, thresholds, DISABLE_THINKING) |
| `agent/llm_client.py` | OpenAI-compatible client + JSON extraction + tắt thinking |
| `agent/parser.py` | Tách header/body/URL, phân loại input (deterministic) |
| `agent/eml_parser.py` | Parse file .eml/.msg/.html → header thật, href ẩn, đính kèm, tín hiệu deterministic |
| `agent/threat_intel.py` | VirusTotal (tùy chọn): domain reputation + file hash lookup, KHÔNG upload |
| `agent/prompts.py` | Prompt templates cho từng model |
| `agent/analyzers.py` | Qwen / Gemma / MiniMax analysis (có fallback) |
| `agent/scoring.py` | Risk scoring engine |
| `agent/report.py` | Tổng hợp báo cáo + render text |
| `agent/pipeline.py` | Orchestration end-to-end (Qwen‖Gemma → MiniMax → score → report) |
| `agent/quiz.py` | Quiz Mode (real vs phishing) |
| `agent/cli.py` | CLI test cục bộ |
| `samples/` | Email mẫu synthetic để demo/test |

---

## Trạng thái hiện tại (đã hoàn thành)

- ✅ Pipeline 3-model chạy end-to-end, phân biệt tốt phishing vs email thật
- ✅ Web chat UI phục vụ ngay từ agent
- ✅ Quiz Mode
- ✅ **Đã deploy LIVE trên AgentBase** — runtime `phishing-guardian`
  (`runtime-6244f9c1-9f92-4284-bceb-64106fab5435`), endpoint:
  `https://endpoint-e93cb03b-ed4f-4eec-ae08-a4291fd22e18.agentbase-runtime.aiplatform.vngcloud.vn`
- ✅ API key MaaS (`phishing-guardian`) + IAM creds đã cấu hình

---

## Checklist công việc (làm được trong 1 ngày)

### ✅ Đã xong — Core & Deploy
- [x] Scaffold project (Custom Agent + OpenAI SDK qua MaaS)
- [x] Cấu hình IAM creds + tạo API key MaaS, wire 3 model paths vào `.env`
- [x] Input parser (tách header/body/URL, phân loại input)
- [x] Prompt engineering cho Qwen / Gemma / MiniMax
- [x] Risk scoring engine (weighted + critical floor)
- [x] Qwen tổng hợp báo cáo tiếng Việt
- [x] Web chat UI + serve từ agent
- [x] Upload file email (.eml/.msg/.html) + drag-drop — khôi phục href ẩn & đính kèm
- [x] Tín hiệu deterministic: link mismatch, đính kèm nguy hiểm, Reply-To mismatch, SPF/DKIM fail
- [x] Unwrap Safe Links/Proofpoint/Mimecast + phát hiện link rút gọn (tránh false positive)
- [x] Email mẫu demo: `samples/eml/` (HR shortener, bank mismatch+exe, legit IT notice)
- [x] VirusTotal enrichment (tùy chọn): domain reputation + file hash lookup, chạy song song với LLM, best-effort (no key → tự tắt). Phát hiện dương tính → NGUY HIỂM; "chưa biết" KHÔNG hạ cảnh giác.
- [x] Quiz Mode
- [x] Build → push → deploy lên AgentBase, verify endpoint ACTIVE + health 200
- [x] Test live: phishing → NGUY HIỂM, email thật → AN TOÀN

### ⬜ P1 — Polish (nâng chất lượng demo)
- [ ] Test thêm nhiều mẫu đa dạng (email tiếng Anh, input rất ngắn, chỉ URL, text không phải email)
- [ ] Tinh chỉnh prompt để giảm hallucination / false positive
- [ ] Cải thiện UI: trạng thái loading, hiển thị URL/sender đã parse, responsive mobile
- [ ] (Nếu kịp) MiniMax vision: phân tích screenshot phishing
- [ ] Xử lý lỗi/timeout thân thiện trên UI

### ⬜ Submission (bắt buộc)
- [ ] Chuẩn bị 2-3 email phishing tiếng Việt ấn tượng cho demo
- [ ] Quay video 2-3 phút: pain point (30s) → giới thiệu (30s) → demo phân tích (1ph) → Quiz (30s)
- [ ] Viết README + mô tả ≤300 từ (problem / user / solution / value)
- [ ] Public/internal GitHub repo + AgentBase project link
- [ ] Double-check mọi required fields trên form, submit trước 17/06 12:00

---

## Quy trình deploy / cập nhật (AgentBase)

Mọi thao tác qua các skill trong `.claude/skills/` (Claude Code):

```
/agentbase-llm        # quản lý API key + model (đã cấu hình)
/agentbase-wizard test  # validate + test cục bộ
/agentbase-deploy     # build → push → tạo/cập nhật runtime (DEFAULT endpoint auto-track)
/agentbase-monitor    # logs / metrics khi debug
/agentbase-teardown   # gỡ toàn bộ resource khi xong
```

Test cục bộ nhanh (không cần deploy):
```bash
source venv/bin/activate
python -m agent.cli --sample hr_phishing      # phân tích email mẫu
python -m agent.cli --eml path/to/email.eml   # phân tích file .eml/.msg/.html
python -m agent.cli --quiz "cập nhật lương"   # quiz mode
python main.py                                 # chạy web UI (lưu ý: cổng 8080 có thể bị Burp chiếm — dùng PORT=8137)
```

---

## Email mẫu phishing tiếng Việt (synthetic — để test & demo)

> Lưu trong `samples/phishing_samples.py`. KHÔNG dùng dữ liệu thật (Rule 9.1).

### Mẫu 1: Giả danh HR
```
Từ: hr.department@vng-corp.com
Tiêu đề: [QUAN TRỌNG] Cập nhật thông tin lương T6/2026

Theo yêu cầu Ban Giám Đốc, phòng Nhân sự cần anh/chị cập nhật thông tin tài khoản
ngân hàng để chi lương đúng hạn. Truy cập link và hoàn tất trong 24 giờ:
https://vng-hr-portal.tk/update-salary-info
Nếu không cập nhật kịp thời, lương tháng 6 có thể bị chậm.
```

### Mẫu 2: Giả danh IT Security
```
Từ: it.security.vng@gmail.com
Tiêu đề: ⚠️ Cảnh báo: Phát hiện đăng nhập bất thường

Hệ thống phát hiện đăng nhập đáng ngờ từ IP không xác định (Russia). Xác minh ngay:
https://vng-security-verify.com/auth?user=employee
Nếu không phải bạn, tài khoản sẽ bị khóa sau 2 giờ.
```

### Mẫu 3: Giả danh ngân hàng (Vietcombank)
```
Từ: cskh@vietcombank-online.net
Tiêu đề: Thông báo giao dịch bất thường - Yêu cầu xác minh

Phát hiện giao dịch 15,000,000 VNĐ lúc 03:42 AM ngày 15/06/2026. Nếu KHÔNG phải bạn:
https://vietcombank-xacminh.com/verify
Link xác minh sẽ hết hạn sau 30 phút.
```

---

## Lưu ý quan trọng từ rulebook

- **KHÔNG dùng data nội bộ thật** — chỉ public/synthetic data (Rule 9.1)
- **Agent phải tuyên bố rõ** người dùng đang tương tác với AI (Rule 11.1) — đã có `ai_disclosure` + badge trên UI
- **Ghi nguồn rõ ràng** nếu dùng open source code (Rule 11.2)
- **Có thể dùng model ngoài** (OpenAI, Anthropic) nhưng phải tự chi trả & khai báo — ưu tiên MaaS
- **Resource giới hạn**: 2 vCPU / 4GB RAM — gọi model qua MaaS API, không self-host
- **Tên agent**: "Phishing Guardian" hoặc "Lá Chắn"
