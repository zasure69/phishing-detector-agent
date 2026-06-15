"""Generate the demo .eml files for Phishing Guardian.

Run:  python samples/eml/build_samples.py

All content is SYNTHETIC (Rule 9.1 — no real internal data). This script is the
single source of truth for the demo set; re-run it to regenerate the files.

File 04 embeds the EICAR anti-malware *test* string — a harmless, industry-standard
file that every antivirus (and VirusTotal) recognizes. It is generated here (not
committed to git) so local AV doesn't quarantine it on checkout. It proves the
VirusTotal *file* hash-lookup path end to end.
"""
import os
from email.message import EmailMessage
from urllib.parse import quote

HERE = os.path.dirname(os.path.abspath(__file__))


def safelink(url: str) -> str:
    """Wrap a URL the way Microsoft Outlook Safe Links does (for unwrap demos)."""
    return ("https://apc01.safelinks.protection.outlook.com/?url="
            + quote(url, safe="") +
            "&data=05%7C02%7Cuser%40vng.com.vn%7Cabc123&sdata=xxx&reserved=0")


def write(name: str, msg: EmailMessage) -> None:
    path = os.path.join(HERE, name)
    with open(path, "wb") as fh:
        fh.write(msg.as_bytes())
    print(f"  {name}  ({os.path.getsize(path)} bytes)")


def build_01_hr_salary() -> EmailMessage:
    m = EmailMessage()
    m["From"] = '"Phong Nhan su VNG" <hr-payroll@vng-hcm-corp.com>'
    m["To"] = "nhanvien@vng.com.vn"
    m["Subject"] = "[KHAN] Cap nhat tai khoan nhan luong thang 6/2026"
    m["Reply-To"] = "payroll.support@vng-hcm-corp.com"
    m["Date"] = "Mon, 15 Jun 2026 08:12:00 +0700"
    m.set_content("Vui long xem ban HTML.")
    link = safelink("https://bit.ly/vng-payroll-update")
    m.add_alternative(f"""<html><body>
<p>Kinh gui Anh/Chi,</p>
<p>Theo yeu cau tu Ban Giam Doc, phong Nhan su can Anh/Chi <b>cap nhat lai thong tin
tai khoan ngan hang</b> de dam bao viec chi luong thang 6 dung han.</p>
<p>Vui long truy cap va hoan tat <b>trong vong 24 gio</b>:<br>
<a href="{link}">https://hr-portal.vng.com.vn/payroll</a></p>
<p>Neu khong cap nhat kip thoi, luong thang 6 co the bi cham.</p>
<p>Tran trong,<br>Phong Nhan su - VNG Group</p>
</body></html>""", subtype="html")
    return m


def build_02_bank() -> EmailMessage:
    m = EmailMessage()
    m["From"] = '"Vietcombank" <no-reply@vcbdigibank-secure.net>'
    m["To"] = "khachhang@vng.com.vn"
    m["Subject"] = "Thong bao giao dich bat thuong - Yeu cau xac minh"
    m["Reply-To"] = "verify@vcb-secure-verify.tk"
    m["Authentication-Results"] = ("mx.vng.com.vn; spf=fail smtp.mailfrom=vcbdigibank-secure.net; "
                                   "dkim=fail; dmarc=fail")
    m["Date"] = "Sun, 15 Jun 2026 03:42:00 +0700"
    m.set_content("Vui long xem ban HTML.")
    m.add_alternative("""<html><body>
<p>Kinh gui Quy khach,</p>
<p>Chung toi phat hien giao dich chuyen khoan <b>15.000.000 VND</b> luc 03:42 ngay 15/06/2026.</p>
<p>Neu KHONG phai giao dich cua Quy khach, vui long xac minh ngay:<br>
<a href="http://vcb-secure-verify.tk/login">https://vietcombank.com.vn/verify</a></p>
<p>Luu y: lien ket se het han sau 30 phut.</p>
<p>Xem chi tiet sao ke trong file dinh kem.</p>
<p>Tran trong,<br>Ngan hang TMCP Ngoai thuong Viet Nam (Vietcombank)</p>
</body></html>""", subtype="html")
    m.add_attachment(b"MZ\x90\x00fake-executable-payload",
                     maintype="application", subtype="octet-stream",
                     filename="SaoKe_GiaoDich_15062026.pdf.exe")
    return m


def build_03_legit() -> EmailMessage:
    m = EmailMessage()
    m["From"] = '"VNG IT Helpdesk" <it-helpdesk@vng.com.vn>'
    m["To"] = "all-staff@vng.com.vn"
    m["Subject"] = "[Thong bao] Bao tri he thong email dinh ky cuoi tuan"
    m["Date"] = "Fri, 12 Jun 2026 17:30:00 +0700"
    m["Authentication-Results"] = "mx.vng.com.vn; spf=pass smtp.mailfrom=vng.com.vn; dkim=pass; dmarc=pass"
    m.set_content("Vui long xem ban HTML.")
    a = safelink("https://www.vng.com.vn/it/maintenance")
    b = safelink("https://login.microsoftonline.com")
    m.add_alternative(f"""<html><body>
<p>Chao Anh/Chi,</p>
<p>Bo phan IT thong bao lich bao tri he thong email dinh ky vao <b>Chu nhat 14/06/2026,
22:00 - 23:00</b>. Trong khung gio nay email co the gian doan trong vai phut.</p>
<p>Thong tin chi tiet: <a href="{a}">www.vng.com.vn/it/maintenance</a></p>
<p>Sau bao tri, neu can dang nhap lai, vui long dung cong chinh thuc:
<a href="{b}">login.microsoftonline.com</a></p>
<p>Khong co hanh dong nao can thuc hien tu phia Anh/Chi. Cam on.</p>
<p>VNG IT Helpdesk</p>
</body></html>""", subtype="html")
    return m


def build_04_malware_attachment() -> EmailMessage:
    # EICAR standard anti-malware test string, assembled from parts so this
    # source file itself is not a scannable EICAR sample.
    eicar = (rb"X5O!P%@AP[4\PZX54(P^)7CC)7}" + rb"$EICAR-STANDARD-"
             + rb"ANTIVIRUS-TEST-FILE!$H+H*")
    m = EmailMessage()
    m["From"] = '"Ke toan" <ketoan@hoadon-dientu.tk>'
    m["To"] = "nhanvien@vng.com.vn"
    m["Subject"] = "Hoa don dien tu thang 6 - Vui long xac nhan"
    m["Date"] = "Mon, 15 Jun 2026 09:00:00 +0700"
    m.set_content("Vui long mo file dinh kem de xem hoa don.")
    m.add_alternative("""<html><body>
<p>Kinh gui Anh/Chi,</p>
<p>Hoa don dien tu thang 6 da duoc phat hanh. Vui long mo file dinh kem de kiem tra
va xac nhan.</p>
<p>Tran trong,<br>Phong Ke toan</p>
</body></html>""", subtype="html")
    # Named .docx (benign extension) on purpose: only VirusTotal's hash lookup
    # can flag it, proving the VT file path (not the extension heuristic).
    m.add_attachment(eicar, maintype="application", subtype="octet-stream",
                     filename="HoaDon_T6_2026.docx")
    return m


def main() -> None:
    print("Generating demo .eml files in samples/eml/ ...")
    write("01_phishing_hr_salary.eml", build_01_hr_salary())
    write("02_phishing_bank_vcb.eml", build_02_bank())
    write("03_legit_it_notice.eml", build_03_legit())
    write("04_phishing_malware_attachment.eml", build_04_malware_attachment())
    print("Done. (04 is git-ignored: it carries the EICAR AV test signature.)")


if __name__ == "__main__":
    main()
