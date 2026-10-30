# Kế hoạch thực hiện đề tài

**Đề tài:** Giám sát và ngăn chặn tấn công Brute Force Web Login

**Môn học:** Giám sát an toàn thông tin (bậc thạc sĩ)

**Quy mô nhóm:** 5 thành viên

**Sản phẩm:** báo cáo đề tài và hệ thống thực nghiệm

## 1. Yêu cầu và phạm vi

### 1.1. Yêu cầu của đề bài

- Thu thập access log của HAProxy/Nginx về Wazuh SIEM.
- Cấu hình rule đếm phản hồi HTTP 401/200 theo IP nguồn.
- Tự động chặn IP thông qua Cloudflare API hoặc iptables.

### 1.2. Phần mở rộng

Nhóm chọn 2–3 mục trong danh sách sau:

| Mã | Nội dung |
|---|---|
| E1 | Phát hiện brute force thành công: một IP có chuỗi 401 rồi đến 200 thì sinh cảnh báo mức cao |
| E2 | Phát hiện tấn công phân tán: nhiều IP cùng nhắm vào một username (password spraying, credential stuffing) |
| E3 | Chặn sớm tại proxy bằng `stick-table` (HAProxy) hoặc `limit_req` (Nginx), so sánh với chặn qua SIEM |
| E4 | Gửi cảnh báo qua Telegram, Slack hoặc email bằng Wazuh integration |
| E5 | Ánh xạ cảnh báo sang MITRE ATT&CK T1110.001, T1110.003, T1110.004 |

## 2. Kiến trúc thực nghiệm

```
[Kali – attacker]
   │ Hydra / Burp Intruder / script Python
   ▼
[Cloudflare (proxy + Tunnel)] ──(nhánh 2)
   │
   ▼
[VM Web: Nginx/HAProxy → ứng dụng login]  ← Wazuh agent đọc access.log
   │                                         ↑ Active Response: iptables
   ▼                                         │
[VM Wazuh all-in-one: manager + indexer + dashboard] ── Active Response: Cloudflare API
```

- **Wazuh:** triển khai all-in-one hoặc Docker single-node, cần khoảng 4 vCPU và 8 GB RAM.
- **Nhánh 1, truy cập trực tiếp:** chặn bằng iptables trên VM web.
- **Nhánh 2, đi qua Cloudflare:** chặn bằng Cloudflare IP Access Rules API.

## 3. Các điểm kỹ thuật cần xử lý

1. **Mã trạng thái 401.** Phần lớn form đăng nhập trả về 200 (kèm thông báo lỗi) hoặc 302 khi đăng nhập sai. Để đếm được 401/200, nhóm dùng một trong hai cách:
   - tự viết ứng dụng đăng nhập (Flask hoặc Node) trả 401 khi sai, 200 khi đúng;
   - dùng `auth_basic` của Nginx.

   Báo cáo cần nêu đây là giới hạn của phương pháp phát hiện dựa trên mã trạng thái.
2. **IP thật của client.** Khi đi qua Cloudflare, Nginx chỉ nhận IP của Cloudflare. Cần cấu hình:
   - Nginx: `real_ip_header CF-Connecting-IP` và `set_real_ip_from` với dải IP của Cloudflare;
   - HAProxy: `option forwardfor`.

   Thiếu cấu hình này, rule đếm sai IP và iptables có thể chặn nhầm IP của Cloudflare.
3. **Giới hạn của iptables.** Khi đi qua Cloudflare, kết nối đến VM web xuất phát từ IP của Cloudflare. iptables không chặn được attacker trong trường hợp này, nên việc chặn phải thực hiện ở biên Cloudflare.
4. **Rule Wazuh.** Đặt trong `local_rules.xml`, ID bắt đầu từ 100100:
   - **Rule cơ sở:** request tới `/login` trả về 401, level 5.
   - **Rule tương quan:** `frequency="10" timeframe="60"` kết hợp `<same_source_ip/>`, level 10. Rule này kích hoạt Active Response.
   - **Rule E1:** phản hồi 200 xuất hiện sau rule tương quan, dùng `if_matched_sid` và `same_source_ip`, level 12 trở lên.

   Dùng lại decoder `web-accesslog` có sẵn. Chỉ viết decoder riêng khi đổi định dạng log.
5. **Active Response.**
   - `firewall-drop` có sẵn trong Wazuh, đặt timeout để tự gỡ chặn.
   - Script Cloudflare viết bằng Python, đặt tại `/var/ossec/active-response/bin/`. Script đọc JSON từ stdin, xử lý hai lệnh `add` và `delete`, và tuân theo giao thức `check_keys` để hỗ trợ timeout.
   - Khai báo `<white_list>` cho IP quản trị.
6. **Điều kiện để dùng Cloudflare.**
   - Một tên miền đã đưa lên Cloudflare (gói Free).
   - Một API token có quyền ghi Firewall.
   - Cloudflare Tunnel (`cloudflared`) để đưa lab ra Internet mà không cần IP công khai.

## 4. Phân công

| TV | Vai trò | Sản phẩm chính |
|---|---|---|
| 1 | Trưởng nhóm, kiến trúc, tổng hợp | Sơ đồ kiến trúc, quản lý repo và tiến độ, ghép báo cáo |
| 2 | Hạ tầng web | VM, ứng dụng đăng nhập, Nginx/HAProxy, định dạng log, real IP, Cloudflare Tunnel |
| 3 | Wazuh SIEM | Cài đặt Wazuh và agent, decoder, rule, dashboard |
| 4 | Active Response | `firewall-drop`, script Cloudflare, whitelist, timeout |
| 5 | Thực nghiệm | Script tấn công, kịch bản kiểm thử, thu thập số liệu |

## 5. Tiến độ

Giả định thời gian thực hiện là 6 tuần, sẽ điều chỉnh theo hạn nộp.

| Tuần | Công việc | Mốc hoàn thành |
|---|---|---|
| 1 | Nghiên cứu lý thuyết, chốt kiến trúc, chọn Nginx/HAProxy, chuẩn bị tên miền | Sơ đồ kiến trúc, đề cương báo cáo |
| 2 | Dựng VM, Wazuh, ứng dụng đăng nhập, proxy | Log hiển thị trên Wazuh dashboard |
| 3 | Viết decoder/rule 401/200, kiểm thử bằng `wazuh-logtest` | Cảnh báo sinh đúng ngưỡng |
| 4 | Active Response iptables và Cloudflare, whitelist, timeout | IP bị chặn và tự gỡ chặn |
| 5 | Làm phần mở rộng, chạy thực nghiệm, thu số liệu | Bảng số liệu, ảnh chụp màn hình |
| 6 | Viết và ghép báo cáo, quay video demo, làm slide | Báo cáo hoàn chỉnh |

## 6. Thực nghiệm và đánh giá

### 6.1. Kịch bản

| Mã | Kịch bản | Kết quả mong đợi |
|---|---|---|
| S1 | Brute force từ một IP, truy cập trực tiếp (Hydra) | Bị chặn bằng iptables |
| S2 | Brute force qua Cloudflare | Bị chặn tại Cloudflare; iptables không có tác dụng |
| S3 | Brute force thành công (401 rồi 200) | Có cảnh báo mức cao |
| S4 | Tấn công tốc độ thấp, tần suất dưới ngưỡng | Xác định giới hạn phát hiện |
| S5 | Tấn công phân tán từ nhiều IP vào một username (nếu làm E2) | Có cảnh báo theo tài khoản |
| S6 | Người dùng hợp lệ nhập sai mật khẩu 2–3 lần | Không bị chặn |

### 6.2. Chỉ số

- Thời gian từ request đầu tiên đến khi có cảnh báo.
- Thời gian từ request đầu tiên đến khi IP bị chặn.
- Số request lọt qua trước khi IP bị chặn.
- Tỷ lệ cảnh báo sai.
- Ảnh hưởng của ngưỡng phát hiện, ví dụ 5, 10 và 20 lần trong 60 giây.

## 7. Đề cương báo cáo

### Phần đầu

- Trang bìa, trang phụ bìa
- Lời cam đoan
- Lời cảm ơn
- Mục lục
- Danh mục các từ viết tắt
- Danh mục bảng
- Danh mục hình vẽ

### MỞ ĐẦU

1. Tính cấp thiết của đề tài
2. Mục tiêu nghiên cứu
3. Đối tượng và phạm vi nghiên cứu
4. Phương pháp nghiên cứu
5. Bố cục báo cáo

### CHƯƠNG 1. TỔNG QUAN VỀ TẤN CÔNG BRUTE FORCE VÀ GIÁM SÁT AN TOÀN THÔNG TIN

**1.1. Tấn công Brute Force vào chức năng đăng nhập web**
- 1.1.1. Khái niệm và cơ chế hoạt động
- 1.1.2. Phân loại theo MITRE ATT&CK T1110: Password Guessing, Password Spraying, Credential Stuffing
- 1.1.3. Công cụ tấn công phổ biến
- 1.1.4. Dấu hiệu nhận biết trong nhật ký HTTP

**1.2. Hệ thống quản lý sự kiện và thông tin an ninh (SIEM)**
- 1.2.1. Khái niệm và chức năng
- 1.2.2. Kiến trúc và thành phần của Wazuh
- 1.2.3. Cơ chế decoder, rule và tương quan sự kiện
- 1.2.4. Cơ chế Active Response

**1.3. Các thành phần hỗ trợ giám sát và ngăn chặn**
- 1.3.1. Reverse proxy Nginx/HAProxy và định dạng access log
- 1.3.2. Tường lửa iptables
- 1.3.3. Cloudflare và cơ chế IP Access Rules

**1.4. Các nghiên cứu và giải pháp liên quan**
- Fail2ban, rate limiting tại proxy, WAF

**1.5. Kết luận chương 1**

### CHƯƠNG 2. PHÂN TÍCH VÀ THIẾT KẾ GIẢI PHÁP

**2.1. Phân tích yêu cầu**
- 2.1.1. Yêu cầu chức năng
- 2.1.2. Yêu cầu phi chức năng

**2.2. Kiến trúc tổng thể hệ thống**
- 2.2.1. Mô hình triển khai
- 2.2.2. Luồng thu thập và xử lý log

**2.3. Thiết kế thu thập log**
- 2.3.1. Định dạng log và xác định IP thật của client sau proxy/CDN
- 2.3.2. Cấu hình Wazuh agent

**2.4. Thiết kế luật phát hiện**
- 2.4.1. Luật phát hiện đăng nhập thất bại (HTTP 401)
- 2.4.2. Luật tương quan theo tần suất và IP nguồn
- 2.4.3. Luật phát hiện đăng nhập thành công sau chuỗi thất bại (401 → 200)
- 2.4.4. Luật phát hiện tấn công phân tán theo tài khoản *(mở rộng)*

**2.5. Thiết kế cơ chế phản ứng tự động**
- 2.5.1. Chặn IP bằng iptables
- 2.5.2. Chặn IP bằng Cloudflare API
- 2.5.3. Danh sách trắng và thời gian tự gỡ chặn

**2.6. Kết luận chương 2**

### CHƯƠNG 3. TRIỂN KHAI THỰC NGHIỆM VÀ ĐÁNH GIÁ

**3.1. Môi trường thực nghiệm**
- 3.1.1. Mô hình mạng và cấu hình máy
- 3.1.2. Phần mềm và phiên bản sử dụng

**3.2. Triển khai hệ thống**
- 3.2.1. Triển khai ứng dụng web và reverse proxy
- 3.2.2. Triển khai Wazuh và cấu hình luật
- 3.2.3. Triển khai Active Response

**3.3. Kịch bản thực nghiệm**
- 3.3.1. Brute force từ một IP, truy cập trực tiếp
- 3.3.2. Brute force qua Cloudflare
- 3.3.3. Brute force thành công
- 3.3.4. Tấn công tốc độ thấp
- 3.3.5. Tấn công phân tán *(mở rộng)*
- 3.3.6. Người dùng hợp lệ nhập sai mật khẩu

**3.4. Kết quả và đánh giá**
- 3.4.1. Thời gian phát hiện và thời gian ngăn chặn
- 3.4.2. Số yêu cầu lọt qua trước khi bị chặn
- 3.4.3. Cảnh báo sai và ảnh hưởng của ngưỡng phát hiện
- 3.4.4. So sánh hai cơ chế chặn iptables và Cloudflare
- 3.4.5. Hạn chế của giải pháp

**3.5. Kết luận chương 3**

### KẾT LUẬN VÀ HƯỚNG PHÁT TRIỂN

1. Kết quả đạt được
2. Hạn chế
3. Hướng phát triển

### Phần cuối

- **Tài liệu tham khảo:** trình bày theo chuẩn IEEE hoặc APA, tùy quy định của khoa.
- **Phụ lục:**
  - A. Cấu hình Nginx/HAProxy
  - B. Decoder và rule Wazuh
  - C. Script Active Response
  - D. Script tấn công thử nghiệm

### Phân công viết

| Thành viên | Phần phụ trách |
|---|---|
| TV1 | Mở đầu, Kết luận, tổng hợp và định dạng |
| TV2 | 1.3, 2.2, 2.3, 3.1, 3.2.1 |
| TV3 | 1.2, 2.4, 3.2.2 |
| TV4 | 1.4, 2.5, 3.2.3 |
| TV5 | 1.1, 3.3, 3.4 |

## 8. Cấu trúc repo

```
infra/            # hướng dẫn dựng VM hoặc docker-compose, cấu hình nginx/haproxy
wazuh/            # local_decoder.xml, local_rules.xml, đoạn ossec.conf
active-response/  # script Cloudflare
attack/           # script tấn công, kịch bản kiểm thử
docs/             # kế hoạch, báo cáo, sơ đồ, số liệu
```

## 9. Các vấn đề cần chốt

1. Hạn nộp; tiến độ ở mục 5 đang giả định 6 tuần.
2. Tên miền trên Cloudflare; nếu không có, phần chặn qua Cloudflare chỉ dừng ở mức thiết kế.
3. Lựa chọn Nginx, HAProxy hoặc kết hợp cả hai (HAProxy làm load balancer phía trước Nginx).
4. Nơi chạy lab: máy cá nhân (khoảng 16 GB RAM cho 3 VM) hoặc VPS/cloud.
5. Mẫu trình bày báo cáo của khoa (cỡ chữ, lề, cách đánh số).
