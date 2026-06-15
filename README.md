# Phishing Guardian 🛡️

Agent AI phát hiện email/tin nhắn **lừa đảo (phishing)**, tối ưu cho **tiếng Việt**.
Người dùng **dán nội dung**, **tải file email (.eml/.msg/.html)** hoặc **gửi ảnh chụp màn hình**
(qua web hoặc Microsoft Teams) → agent phân tích đa chiều qua nhiều model AI + tra cứu
VirusTotal → trả về **điểm an toàn (0–100)**, **danh sách dấu hiệu** và **khuyến nghị** bằng
tiếng Việt dễ hiểu.

> Built for **Claw-a-thon 2026** (VNG / GreenNode) — track *Agentic Assistant*, platform
> **AgentBase**. Bạn đang tương tác với AI; công cụ không lưu dữ liệu thật.

## 🌐 Dùng thử (live)

Mở link endpoint trên trình duyệt và bắt đầu:

**https://endpoint-e93cb03b-ed4f-4eec-ae08-a4291fd22e18.agentbase-runtime.aiplatform.vngcloud.vn**

Các kênh & input:
- **Web chat** (`GET /`): dán text · tải file `.eml/.msg/.html` · gửi ảnh (📎, kéo-thả, hoặc Ctrl+V dán ảnh).
- **Microsoft Teams**: chat 1:1 với bot, dán nội dung / gửi file / ảnh (xem `teams/`).
- **API** (`POST /invocations`):
  - text: `{"action":"analyze","content":"..."}`
  - file/ảnh: `{"action":"analyze","filename":"mail.eml","content_b64":"<base64>"}`
  - quiz: `{"action":"quiz","topic":"..."}`
- `GET /health` → health check · `POST /api/messages` → Bot Framework (Teams).

## ✨ Điểm nổi bật

- **Đa kênh, đa định dạng**: text, file email, ảnh chụp màn hình — web & Teams.
- **Khôi phục tín hiệu ẩn từ file `.eml/.msg`**: link thật sau text, header (From/Reply-To/SPF/DKIM),
  file đính kèm — những thứ copy-paste bỏ sót.
- **Tín hiệu deterministic** (không cần LLM, đáng tin): mismatch chữ hiển thị ↔ link thật, đuôi
  file nguy hiểm (`.exe`, `.pdf.exe`, macro), link rút gọn, Reply-To khác domain, SPF/DKIM fail.
- **Unwrap URL bọc** (Microsoft Safe Links / Proofpoint / Mimecast) trước khi đánh giá → tránh
  báo nhầm mọi link là giả mạo.
- **VirusTotal** (tuỳ chọn): tra reputation tên miền + hash file (KHÔNG upload nội dung).
- **Ảnh chụp màn hình**: Gemma đọc ảnh (OCR + dấu hiệu thị giác) → đưa vào pipeline.
- **Quiz Mode**: tạo email thật/giả để người dùng đoán.
- **Điểm an toàn** (cao = an toàn) + band màu (🟢🟡🔴) trực quan.

## Kiến trúc

```
Input:  dán text  |  file .eml/.msg/.html  |  ảnh chụp màn hình
          │              │                        │
          │              │ eml_parser.py          │ vision.py (Gemma đọc ảnh)
          │              │ (header thật, unwrap    │
          │              │  Safe Links, href ẩn,   │
          │              │  đính kèm, tín hiệu      │
          ▼              ▼  deterministic)         ▼
                     parser.py — chuẩn hoá input + tách URL
                                    │
          ┌──────────────┬──────────────────┬───────────────┬─────────────────┐
          │  Qwen 3.5    │  Gemma 4 31B-IT  │  MiniMax M2.5 │  VirusTotal     │
          │  ngôn ngữ VN │  structured JSON │  cross-valid. │  reputation/hash│
          └──────┬───────┴────────┬─────────┴───────┬───────┴────────┬────────┘
                 ▼ (song song — đều best-effort, lỗi 1 nhánh không sập pipeline)
                      scoring.py — weighted (40/35/25) + critical floor
                                    │
                      report.py — Qwen tổng hợp báo cáo tiếng Việt
                                    │
        🟢 AN TOÀN (≥70 an toàn) · 🟡 NGHI NGỜ (30–69) · 🔴 NGUY HIỂM (≤29 an toàn)
```

> **Điểm an toàn**: nội bộ engine tính theo *rủi ro* (cao = nguy hiểm); lớp hiển thị đảo thành
> `an toàn = 100 − rủi ro` để trực quan (cao = an toàn). Band + màu giữ nguyên ý nghĩa.

Mọi model OpenAI-compatible gọi qua một `openai` client (chỉ đổi `model`). Qwen 3.5 là
reasoning model → bắt buộc tắt "thinking" (`enable_thinking=false`) để không trả về rỗng.

## Cấu trúc code

| File | Vai trò |
|------|---------|
| `main.py` | AgentBase entrypoint: web UI (`GET /`), API (`POST /invocations`), Teams (`POST /api/messages`), `GET /health` |
| `web/index.html` | Giao diện chat web (text/file/ảnh, kéo-thả, dán ảnh) |
| `agent/config.py` | Cấu hình từ env (model paths, weights, thresholds, VT, Teams) |
| `agent/llm_client.py` | OpenAI-compatible client (text + ảnh) + JSON extraction + tắt thinking |
| `agent/parser.py` | Tách header/body/URL, phân loại input (deterministic) |
| `agent/eml_parser.py` | Parse `.eml/.msg/.html` → header thật, unwrap Safe Links, href ẩn, đính kèm |
| `agent/vision.py` | Đọc ảnh chụp màn hình (Gemma) → text + URL + dấu hiệu thị giác |
| `agent/prompts.py` | Prompt templates cho từng model |
| `agent/analyzers.py` | Qwen / Gemma / MiniMax analysis (degrade gracefully) |
| `agent/threat_intel.py` | VirusTotal: domain reputation + file hash lookup (không upload) |
| `agent/scoring.py` | Risk engine + điểm an toàn |
| `agent/report.py` | Tổng hợp báo cáo + render text |
| `agent/pipeline.py` | Orchestration end-to-end (text / file / ảnh) |
| `agent/teams.py` | Tích hợp Microsoft Teams (Bot Framework, Adaptive Card) |
| `agent/quiz.py` | Quiz Mode |
| `agent/cli.py` | CLI test cục bộ |
| `samples/eml/` | Email mẫu synthetic + bộ demo (xem `samples/eml/README.md`) |
| `teams/` | Teams app package (manifest + icon + zip) — `teams/README.txt` |
| `docs/teams-IT-request.txt` | Tài liệu yêu cầu IT để dựng bot Teams |

## Chạy cục bộ

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env          # điền LLM_API_KEY, model paths; (tuỳ chọn) VT_API_KEY, MICROSOFT_APP_*
```

Lấy API key & model paths từ GreenNode AI Platform (trong Claude Code):
```bash
/agentbase-llm api-keys create     # tạo key → tự lưu .env
/agentbase-llm models list         # xem model paths (modelStatus = ENABLED)
```

Test pipeline qua CLI (không cần deploy):
```bash
python -m agent.cli --sample hr_phishing                # email mẫu (text)
python -m agent.cli --eml samples/eml/02_phishing_bank_vcb.eml   # file .eml/.msg/.html
python -m agent.cli --image screenshot.png              # ảnh chụp màn hình
python -m agent.cli --quiz "cập nhật lương"             # quiz mode
echo "http://vng-hr-portal.tk/login" | python -m agent.cli -
```

Chạy HTTP server cục bộ:
```bash
python main.py        # http://0.0.0.0:8080  (nếu cổng 8080 bận: PORT=8137 python main.py)
```

## API

`POST /invocations` → response gồm:
- `scoring`: `safety_score` (cao = an toàn), `final_score` (rủi ro nội bộ), `band`, `emoji`, `components`
- `analysis`: kết quả từng model · `threat_intel`: kết quả VirusTotal
- `report`: `verdict_line`, `red_flags`, `recommendations` · `display`: bản text render sẵn
- `ai_disclosure`: tuyên bố AI

## Bảo mật theo thiết kế

- **Không tự fetch URL trong email** → tránh SSRF (lộ credential runtime) và bị "cloaking" đánh lừa.
- **VirusTotal chỉ tra cứu** (domain reputation + hash file), **không upload** nội dung file/URL → an toàn dữ liệu.
- **Bot Teams** xác thực JWT do Bot Connector phát hành; secret lưu ở `.env`/runtime, không commit Git.
- **Không lưu dữ liệu thật**; email/ảnh thật **không** đưa vào repo (xem `.gitignore`).

## Deploy lên AgentBase

```bash
# trong Claude Code:
/agentbase-llm                 # cấu hình LLM API key + models
/agentbase-deploy              # build → push → tạo/cập nhật runtime
/agentbase-monitor             # logs / metrics
```

## Tích hợp Microsoft Teams

1. Nhờ IT dựng Azure Bot + app registration (xem `docs/teams-IT-request.txt`).
2. Đặt env trên runtime: `MICROSOFT_APP_ID`, `MICROSOFT_APP_PASSWORD`, `MICROSOFT_APP_TENANT_ID`.
3. Messaging endpoint của Azure Bot trỏ tới `…/api/messages`.
4. Upload `teams/phishing-guardian-teams.zip` vào Teams (xem `teams/README.txt`).

## Lưu ý tuân thủ rulebook

- **Không dùng dữ liệu nội bộ thật** — chỉ synthetic/public (Rule 9.1).
- **Tuyên bố rõ AI** — mọi response/Teams card kèm `ai_disclosure` (Rule 11.1).
- **Model qua MaaS** — không self-host (giới hạn 2 vCPU / 4GB).
- Dùng dịch vụ ngoài (VirusTotal, Microsoft Teams) được khai báo trong README.
