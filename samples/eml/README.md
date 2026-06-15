# Bộ email mẫu để Demo 🎬

Toàn bộ **synthetic** (không dùng dữ liệu thật — Rule 9.1). Dùng để demo Phishing Guardian
một cách nhất quán, mỗi file minh hoạ một nhóm tính năng.

## Cách dùng

**Web UI (khuyến nghị cho demo):** mở endpoint → bấm 📎 hoặc **kéo-thả** file `.eml` vào khung chat.

**CLI (kiểm tra nhanh):**
```bash
source venv/bin/activate
python -m agent.cli --eml samples/eml/01_phishing_hr_salary.eml
```

**Sinh lại toàn bộ file mẫu:**
```bash
python samples/eml/build_samples.py
```

## Bảng tổng hợp

| File | Kết quả mong đợi | Minh hoạ tính năng |
|------|------------------|--------------------|
| `01_phishing_hr_salary.eml` | 🔴 **NGUY HIỂM** (~95) | Giả danh HR, lookalike domain `vng-hcm-corp.com`, tạo áp lực 24h. Link bọc **Safe Links** → **giải mã ra `bit.ly`** → phát hiện **link rút gọn**. |
| `02_phishing_bank_vcb.eml` | 🔴 **NGUY HIỂM** (100) | Giả danh Vietcombank. **Deterministic critical**: link hiển thị `vietcombank.com.vn` nhưng href thật `vcb-secure-verify.tk` (mismatch) + đính kèm **`.pdf.exe`** (đuôi kép) + **SPF/DKIM/DMARC fail** + Reply-To khác domain. |
| `03_legit_it_notice.eml` | 🟢 **AN TOÀN** (~10–15) | Email IT nội bộ **hợp lệ**, link cũng bị **Safe Links bọc** nhưng đích thật là `vng.com.vn` / `microsoftonline.com`. **Chứng minh KHÔNG báo nhầm** (no false positive). |
| `04_phishing_malware_attachment.eml` ⚠️ | 🔴 **NGUY HIỂM** | Đính kèm **`HoaDon_T6_2026.docx`** (tên vô hại) nhưng là file test **EICAR** → **VirusTotal phát hiện ~64/75 antivirus**. Chứng minh **VT check file đính kèm** (đuôi `.docx` không bị heuristic gắn cờ → chỉ VT bắt được). *Cần `VT_API_KEY`.* |

## Kịch bản demo gợi ý (2–3 phút)

1. **`03`** trước — cho thấy email công ty thật → 🟢 AN TOÀN (tạo lòng tin, chứng minh không báo bừa).
2. **`01`** — phishing HR, mở mục "Đối chiếu VirusTotal" + cho thấy link Safe Links được **giải mã ra bit.ly**.
3. **`02`** — phishing ngân hàng → 100/100, chỉ ra mismatch link + file `.pdf.exe` + SPF fail.
4. **`04`** — kéo file vào → VirusTotal báo **64/75 antivirus phát hiện mã độc** (điểm nhấn mạnh nhất).
5. (Tuỳ chọn) Dán text thẳng vào chat — dùng các **nút mẫu** có sẵn trên UI (HR / IT / ngân hàng) để demo luồng copy-paste.

## Ghi chú

- **`04` không được commit lên git** (chứa chữ ký test EICAR — phần mềm diệt virus có thể cách ly khi clone). Chạy `build_samples.py` để tạo lại trên máy bạn.
- **EICAR** là file test chuẩn, **vô hại**, được mọi hãng antivirus công nhận để kiểm thử — không phải mã độc thật.
- VirusTotal free: **4 request/phút, 500/ngày**. Nếu demo đông người bấm cùng lúc có thể bị giới hạn → mục VT sẽ tự bỏ qua, verdict vẫn chạy bằng heuristic + LLM.
- File `04` cần đã cấu hình `VT_API_KEY` thì mới thấy kết quả VirusTotal cho đính kèm.
