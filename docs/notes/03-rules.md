# 03. Decoder và rule phát hiện

## Mục tiêu
Viết rule phát hiện brute force trên `/login` cho từng nhánh, rule E1 (đăng nhập thành công sau brute force) và E2 (một tài khoản bị thử từ nhiều IP), kèm bộ kiểm thử tự động.

## Môi trường và phiên bản
- Wazuh manager 4.14.10 (container `kmam-wazuh-wazuh.manager-1`)
- Rule có sẵn được kế thừa: `0245-web_rules.xml` (31100, 31101, 31108) và decoder `web-accesslog`, `json`

## Các bước thực hiện
### Khảo sát rule có sẵn (2026-11-10)
- 31100 (level 0) gom mọi dòng access log; 31101 (level 5) là rule con của 31100 với `<id>^4</id>` (mã 4xx).
- 31108 (level 0) là rule con của 31100 với `<id>^2|^3</id>` và `compiled_rule is_simple_http_request`. Rule này khớp cả `POST /login` trả 200 (xác nhận bằng kiểm thử, xem mục Sự cố).
- 31151 (level 10, T1595.002) kích hoạt khi có 14 lần 4xx trong 90 giây từ cùng IP. Với tải brute force đủ dài, rule này sẽ kích hoạt song song với 100101/100111; trong lần kiểm tra luồng thật dưới đây (10 lần mỗi nhánh), rule này chưa kích hoạt. Active Response chỉ gắn với 100101/100111 (giai đoạn 4, 5).
- Không cần decoder riêng, nên không tạo `wazuh/decoders/local_decoder.xml`.

### Viết rule (2026-11-10)
- File: [wazuh/rules/local_rules.xml](../../wazuh/rules/local_rules.xml), mount read-only vào `/var/ossec/etc/rules` ([infra/wazuh/docker-compose.yml](../../infra/wazuh/docker-compose.yml)). Mount theo thư mục, nên sau khi `git pull` chỉ cần `wazuh-control restart` trong container.
- Tách nhánh bằng `<location>access-direct.log</location>` và `<location>access-cf.log</location>`; giá trị là chuỗi con của đường dẫn file log.
- 100101/100111: `frequency="10" timeframe="60"`, `if_matched_sid` là 100100/100110, `<same_srcip />`.
- E1 (100105): làm theo mẫu rule 40112 có sẵn ("authentication failures followed by a success"): `if_group kmam_login_success`, `if_matched_group kmam_bruteforce`, `same_srcip`, `timeframe="600"`. Cần thêm hai rule trung gian level 0 là 100102/100112 cho request 200 trên `/login`.
- E2 (100121): `frequency="6" timeframe="300"`, `if_matched_sid 100120`, `<same_user />`, `<different_srcip />`. Decoder `json` ánh xạ khóa `user` sang trường tĩnh `dstuser` (giai đoạn 2), và `same_user` so sánh trường này.
- Thẻ `<mitre>`: T1110.001 cho 100101/100111, T1110 cho 100105, T1110.003 cho 100121.

### Bộ kiểm thử (2026-11-10)
- File: [wazuh/tests/test_rules.py](../../wazuh/tests/test_rules.py). Script chỉ dùng thư viện chuẩn, chạy bằng Python có sẵn trong image manager, nhận mã qua stdin:
  ```
  cd infra/wazuh
  docker compose exec -T wazuh.manager /var/ossec/framework/python/bin/python3 - < ../../wazuh/tests/test_rules.py
  ```
- Script gửi từng dòng log mẫu tới socket `/var/ossec/queue/sockets/logtest` (header 4 byte little-endian và nội dung JSON, như module `wazuh.core.wazuh_socket` của manager), kèm `location` và `log_format` của file log tương ứng. Mỗi tình huống dùng một session logtest riêng, nên bộ đếm `frequency` bắt đầu từ 0.
- Lý do không dùng lệnh `wazuh-logtest` tương tác: lệnh này gán location là `stdin`, nên các rule có `<location>` không khớp.

## Kết quả kiểm tra
### Bộ kiểm thử
16/16 tình huống đạt (ảnh: `images/03-logtest.png`). Các tình huống chính:
- 9 lần 401 cho 100100, lần thứ 10 cho 100101; tương tự 100110/100111 trên nhánh cf.
- 5 + 5 lần 401 từ hai IP xen kẽ: không có 100101.
- 401 trên URL khác `/login`: dừng ở 31101.
- 10 lần 401 rồi 200 từ cùng IP: 100105 trên cả hai nhánh; 200 từ IP khác: 100102.
- `login_failed` cho 100120; `login_success` không khớp 100120.
- 6 lần thất bại, cùng user, 6 IP: lần thứ 6 cho 100121. Cùng user một IP, hoặc 6 user khác nhau: không có 100121.
- 5 lần từ IP A rồi 1 lần từ IP B, cùng user: 100121 kích hoạt (giới hạn của `different_srcip`, xem dưới).

### Luồng thật (2026-11-10, 03:53 UTC)
Từ Kali, gửi 10 lần mật khẩu sai rồi 1 lần đúng qua nhánh direct (`http://100.109.212.65/login`, qua Tailscale), sau đó lặp lại qua nhánh cf (`https://monitor-lab.nguyencongthanh.io.vn/login`). Cảnh báo trong `alerts.json` của manager:

| Rule | Level | File | srcip | Số lần | Thời điểm đầu (UTC) |
|---|---|---|---|---|---|
| 100100 | 5 | access-direct.log | 100.86.126.91 | 9 | 03:53:08.761 |
| 100101 | 10 | access-direct.log | 100.86.126.91 | 1 | 03:53:11.330 |
| 100105 | 13 | access-direct.log | 100.86.126.91 | 1 | 03:53:11.698 |
| 100110 | 5 | access-cf.log | 42.118.107.36 | 9 | 03:53:12.760 |
| 100111 | 10 | access-cf.log | 42.118.107.36 | 1 | 03:53:18.764 |
| 100105 | 13 | access-cf.log | 42.118.107.36 | 1 | 03:53:19.332 |
| 100120 | 3 | auth.json | 100.86.126.91 | 10 | 03:53:08.765 |
| 100120 | 3 | auth.json | 42.118.107.36 | 9 | 03:53:14.763 |
| 100121 | 10 | auth.json | 42.118.107.36 | 1 | 03:53:12.762 |

- 100121 kích hoạt vì cùng user `admin` thất bại từ hai IP (`100.86.126.91` qua nhánh direct, `42.118.107.36` qua nhánh cf). Đây là trường hợp giới hạn đã nêu: hai IP là đủ để rule kích hoạt.
- Ảnh dashboard: `images/03-alerts-dashboard.png` (Threat Hunting, truy vấn `rule.id:(100101 or 100105 or 100111 or 100121)`, giờ hiển thị theo UTC+7).

## Sự cố và phương án bị loại
- Hiện tượng: `wazuh-analysisd: ERROR: Invalid option 'same_dstuser' for rule '100121'`, kèm `CRITICAL: (1220): Error loading the rules`. / Nguyên nhân: Wazuh 4.14 không có tùy chọn `same_dstuser`. / Cách xử lý: dùng `<same_user />`, tùy chọn so sánh trường `dstuser`.
- Hiện tượng: request 200 `POST /login` khớp 31108 ("Ignored URLs (simple queries)"), không khớp 100102/100112, nên 4 tình huống E1 thất bại. / Nguyên nhân: 31108 là rule con của 31100 và được xét trước rule cục bộ. / Cách xử lý: 100102/100112 dùng `<if_sid>31100, 31108</if_sid>`.
- Giới hạn chưa xử lý của E2: Wazuh không có phép đếm số IP phân biệt, nên 100121 không bảo đảm có 6 IP khác nhau. Kiểm thử cuối cùng trong `test_rules.py` ghi lại hành vi này.

## Ghi chú cho báo cáo
- Mục 2.4: bảng rule (ID, điều kiện, level, MITRE), cây kế thừa 31100 → 31101 → 100100/100110 và 31100/31108 → 100102/100112, cách tách nhánh bằng `<location>`, mẫu `if_group` + `if_matched_group` cho E1, giới hạn của `different_srcip` cho E2.
- Mục 3.2.2: kết quả 16/16 tình huống (ảnh `03-logtest.png`), bảng cảnh báo của luồng thật, ảnh `03-alerts-dashboard.png`; nêu rule 31151 có sẵn cũng kích hoạt khi có tải.
