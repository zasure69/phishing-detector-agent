"""Synthetic sample messages for demo and local testing (Rule 9.1: no real data).

Lifted from the project brief (CLAUDE.md). Used by `python -m agent.cli`
and for the demo script.
"""

SAMPLES = {
    "hr_phishing": """Từ: hr.department@vng-corp.com
Tiêu đề: [QUAN TRỌNG] Cập nhật thông tin lương T6/2026

Xin chào anh/chị,

Theo yêu cầu từ Ban Giám Đốc, phòng Nhân sự cần anh/chị cập nhật lại thông tin tài khoản ngân hàng để đảm bảo việc chi lương tháng 6 được thực hiện đúng hạn.

Vui lòng truy cập link bên dưới và hoàn tất trong vòng 24 giờ:
👉 https://vng-hr-portal.tk/update-salary-info

Nếu không cập nhật kịp thời, lương tháng 6 có thể bị chậm.

Trân trọng,
Phòng Nhân sự - VNG Group""",

    "it_security_phishing": """Từ: it.security.vng@gmail.com
Tiêu đề: ⚠️ Cảnh báo: Phát hiện đăng nhập bất thường trên tài khoản của bạn

Hệ thống bảo mật đã phát hiện hoạt động đăng nhập đáng ngờ trên tài khoản email công ty của bạn từ địa chỉ IP không xác định (Russia).

Để bảo vệ tài khoản, vui lòng xác minh danh tính ngay:
🔐 https://vng-security-verify.com/auth?user=employee

Nếu đây không phải bạn, tài khoản sẽ tự động bị khóa sau 2 giờ.

IT Security Team
VNG Corporation""",

    "bank_phishing": """Từ: cskh@vietcombank-online.net
Tiêu đề: Thông báo giao dịch bất thường - Yêu cầu xác minh

Kính gửi Quý khách,

Chúng tôi phát hiện giao dịch chuyển khoản 15,000,000 VNĐ từ tài khoản của Quý khách vào lúc 03:42 AM ngày 15/06/2026.

Nếu đây KHÔNG phải giao dịch của Quý khách, vui lòng xác minh ngay:
https://vietcombank-xacminh.com/verify

Lưu ý: Link xác minh sẽ hết hạn sau 30 phút.

Trân trọng,
Ngân hàng TMCP Ngoại thương Việt Nam (Vietcombank)
Hotline: 1900 545 413""",

    "legit_example": """Từ: no-reply@notifications.github.com
Tiêu đề: [GitHub] A new SSH key was added to your account

Hi there,

A new SSH key was added to your GitHub account. If you recently added this
key, you can safely ignore this email.

If you did not add this key, please review your account security settings:
https://github.com/settings/keys

Thanks,
The GitHub Team""",
}
