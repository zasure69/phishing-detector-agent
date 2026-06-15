# Phishing Guardian 🛡️

Agent AI phát hiện email/tin nhắn **lừa đảo phishing**, tối ưu cho **tiếng Việt**.
Mọi nhân viên mở **giao diện chat web** (không cần cài app), dán nội dung email / URL /
tin nhắn đáng ngờ → agent phân tích đa chiều qua 3 model AI → trả về **mức độ rủi ro
(0-100)**, **danh sách dấu hiệu**, và **khuyến nghị hành động** bằng tiếng Việt dễ hiểu.

> Built for **Claw-a-thon 2026** (VNG / GreenNode) — track *Agentic Assistant*,
> platform **AgentBase**. Bạn đang tương tác với AI.

## 🌐 Dùng thử (live)

Mở link endpoint trên trình duyệt và bắt đầu dán nội dung đáng ngờ:

**https://endpoint-e93cb03b-ed4f-4eec-ae08-a4291fd22e18.agentbase-runtime.aiplatform.vngcloud.vn**

- `GET /` → giao diện chat web (dán text **hoặc** tải file .eml/.msg/.html, kéo-thả)
- `POST /invocations` → API:
  - dán text: `{"action":"analyze","content":"..."}`
  - tải file: `{"action":"analyze","filename":"mail.eml","content_b64":"<base64>"}`
  - quiz: `{"action":"quiz","topic":"..."}`
- `GET /health` → health check

Tải file `.eml/.msg` giúp phát hiện **link ẩn sau text** và **tệp đính kèm nguy hiểm** mà
copy-paste sẽ bỏ sót (mismatch chữ hiển thị ↔ href, đuôi .exe/.pdf.exe, Reply-To khác
domain, SPF/DKIM fail).

## Kiến trúc

```
Input (email / URL / text)
   │  parser.py — tách sender / subject / body / URLs (deterministic)
   ▼
┌─────────────────┬──────────────────────┬─────────────────────┐
│  Qwen 3.5       │  Gemma 4 31B-IT      │  MiniMax M2.5       │
│  ngôn ngữ VN    │  structured JSON     │  cross-validation   │
└────────┬────────┴──────────┬───────────┴──────────┬──────────┘
         ▼ (song song)        ▼                       ▼
              scoring.py — weighted aggregation (40/35/25)
              + critical-flag floor (≥70 nếu có cờ critical)
                              ▼
              report.py — Qwen tổng hợp báo cáo tiếng Việt
                              ▼
        🟢 AN TOÀN (0-30) · 🟡 NGHI NGỜ (31-70) · 🔴 NGUY HIỂM (71-100)
```

Mỗi model OpenAI-compatible nên gọi qua một `openai` client duy nhất, chỉ đổi
`model` (xem `agent/config.py`). Qwen + Gemma chạy song song; MiniMax phụ thuộc
kết quả của cả hai. Mọi analyzer **degrade gracefully** — lỗi 1 model không làm
sập pipeline.

## Cấu trúc code

| File | Vai trò |
|------|---------|
| `main.py` | AgentBase entrypoint (`POST /invocations`, `GET /health`) |
| `agent/config.py` | Cấu hình từ env (model IDs, weights, thresholds) |
| `agent/llm_client.py` | OpenAI-compatible client + JSON extraction |
| `agent/parser.py` | Tách header/body/URL, phân loại input (no LLM) |
| `agent/prompts.py` | Prompt templates cho từng model |
| `agent/analyzers.py` | Qwen / Gemma / MiniMax analysis functions |
| `agent/scoring.py` | Risk scoring engine |
| `agent/report.py` | Tổng hợp báo cáo + render text |
| `agent/pipeline.py` | Orchestration end-to-end |
| `agent/quiz.py` | Quiz Mode (real vs phishing) |
| `agent/cli.py` | CLI test cục bộ |
| `samples/` | Email mẫu synthetic để demo/test |

## Chạy cục bộ

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env          # điền LLM_API_KEY (xem /agentbase-llm), model IDs
```

Lấy API key & model IDs từ GreenNode AI Platform:

```bash
# trong Claude Code:
/agentbase-llm api-keys create     # tạo key → tự lưu vào .env
/agentbase-llm models list         # xem model IDs (modelStatus = ENABLED)
```

Test pipeline qua CLI (không cần deploy):

```bash
python -m agent.cli --sample hr_phishing     # phân tích email mẫu
python -m agent.cli --file suspicious.txt     # phân tích file
echo "https://vng-hr-portal.tk/login" | python -m agent.cli -
python -m agent.cli --quiz "cập nhật lương"   # quiz mode
```

Chạy HTTP server cục bộ:

```bash
python main.py        # http://0.0.0.0:8080
curl -X POST http://127.0.0.1:8080/invocations \
  -H "Content-Type: application/json" \
  -d '{"action":"analyze","content":"Từ: hr@vng-corp.tk\nVui lòng xác nhận trong 24h: http://vng-hr.tk"}'
curl http://127.0.0.1:8080/health
```

## API

`POST /invocations`

```jsonc
// Phân tích
{"action": "analyze", "content": "<email / URL / text>"}
// Quiz
{"action": "quiz", "topic": "<chủ đề tuỳ chọn>"}
```

Response (analyze) gồm: `scoring` (final_score, band, components),
`analysis` (kết quả 3 model), `report` (verdict, red_flags, recommendations),
và `display` (báo cáo text render sẵn).

## Deploy lên AgentBase

```bash
# trong Claude Code:
/agentbase-llm                 # cấu hình LLM API key + models
/agentbase-wizard test         # validate + test cục bộ
/agentbase-deploy              # build → push → tạo runtime
/agentbase-monitor             # logs / metrics sau khi deploy
```

## Lưu ý tuân thủ rulebook

- **Không dùng dữ liệu nội bộ thật** — chỉ synthetic/public (Rule 9.1).
- **Tuyên bố rõ AI** — mọi response kèm `ai_disclosure` (Rule 11.1).
- **Model qua MaaS** — không self-host (giới hạn 2 vCPU / 4GB).
- Nếu dùng model ngoài (OpenAI/Anthropic), khai báo trong README và tự chi trả.
