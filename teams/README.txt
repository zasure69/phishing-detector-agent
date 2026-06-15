PHISHING GUARDIAN - TEAMS APP PACKAGE
=====================================

File để upload: phishing-guardian-teams.zip
(gồm manifest.json + color.png + outline.png)

Tạo lại package:  python teams/make_package.py
(sửa BOT_ID / ENDPOINT_DOMAIN trong make_package.py nếu thay đổi)


CÁCH UPLOAD VÀO TEAMS
---------------------
A) Thử nhanh (sideload - cần Teams Admin cho phép "upload custom app"):
   Teams -> Apps -> Manage your apps -> Upload an app -> Upload a custom app
   -> chọn phishing-guardian-teams.zip -> Add.
   Sau đó mở chat 1:1 với "Phishing Guardian" và dán nội dung để thử.

B) Phát hành cho công ty (Teams Admin):
   Teams Admin Center -> Teams apps -> Manage apps -> Upload new app
   -> tải zip -> phê duyệt -> gán policy cho nhóm pilot.


ĐIỀU KIỆN ĐỂ BOT TRẢ LỜI ĐƯỢC
-----------------------------
1. Azure Bot đã bật kênh Microsoft Teams.
2. Messaging endpoint của Azure Bot trỏ tới:
   https://endpoint-e93cb03b-ed4f-4eec-ae08-a4291fd22e18.agentbase-runtime.aiplatform.vngcloud.vn/api/messages
3. Runtime AgentBase đang chạy (endpoint /api/messages trả 401 với request không hợp lệ = đúng).
4. Biến môi trường trên runtime: MICROSOFT_APP_ID, MICROSOFT_APP_PASSWORD, MICROSOFT_APP_TENANT_ID.


GHI CHÚ
-------
- TEAMS_APP_ID trong manifest là GUID của app Teams (khác BOT_ID). Đổi nếu bị trùng.
- MVP hỗ trợ tin nhắn dạng chữ (dán nội dung). Ảnh/file gửi qua Teams sẽ bổ sung sau.
- Nếu URL endpoint AgentBase đổi: cập nhật ENDPOINT_DOMAIN + chạy lại make_package.py,
  và nhờ IT cập nhật messaging endpoint của Azure Bot.
