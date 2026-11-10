# 02. Wazuh manager và agent

## Mục tiêu
Dựng Wazuh manager (kèm indexer và dashboard) bằng Docker, cài agent trên host và đưa ba nguồn log của giai đoạn 1 vào Wazuh.

## Môi trường và phiên bản
- Wazuh manager, indexer, dashboard: 4.14.10 (image `wazuh/wazuh-*:4.14.10`), dựa trên `wazuh-docker` tag `v4.14.10`, thư mục `single-node`
- Bộ sinh chứng chỉ: `wazuh/wazuh-certs-generator:0.0.5`
- Wazuh agent: gói `wazuh-agent` 4.14.10-1 từ kho `packages.wazuh.com/4.x/apt`, cài trên host Ubuntu 26.04.1 (resolute)

## Các bước thực hiện
### Chọn phiên bản và cấu hình (2026-11-10)
- Bản ổn định mới nhất tại thời điểm triển khai: 4.14.10 (phát hành 2026-11-09). Bản 5.0 còn ở rc2 nên không dùng.
- Cấu hình: [infra/wazuh/](../../infra/wazuh/). Các điểm khác với bản gốc của `wazuh-docker`:
  - Port 1514, 1515 chỉ publish trên `127.0.0.1`, vì agent duy nhất chạy trên chính host. Không publish 9200 (indexer), 55000 (API), 514/udp (syslog), vì không có client nào ngoài các container cần đến.
  - Dashboard publish trên `100.109.212.65:443` (IP Tailscale của server), tức là chỉ truy cập được qua đường quản trị.
  - Mật khẩu của `admin`, `kibanaserver` (indexer) và `wazuh-wui` (API) lấy từ `infra/wazuh/.env`, được sinh ngẫu nhiên trên server. [set-passwords.sh](../../infra/wazuh/set-passwords.sh) sinh `internal_users.yml` từ template, chỉ gồm `admin` và `kibanaserver`; các user demo của bản gốc (`kibanaro`, `logstash`, `readall`, `snapshotrestore`) bị bỏ vì mật khẩu của chúng công khai.
  - Không mount `wazuh.yml` của dashboard; entrypoint của image tự ghi file này từ biến `API_PASSWORD`, nên repo không chứa mật khẩu API.
  - Mount [wazuh/agent.conf](../../wazuh/agent.conf) vào `/var/ossec/etc/shared/default/agent.conf` của manager. Manager đẩy cấu hình `localfile` xuống agent thuộc nhóm `default`, nên không phải sửa `ossec.conf` trên host ngoài địa chỉ manager.
- `vm.max_map_count` trên host đã là 1048576 (lớn hơn mức 262144 mà indexer yêu cầu), không cần thay đổi.

### Sinh mật khẩu, chứng chỉ và khởi động (2026-11-10)
- `infra/wazuh/.env` tạo với quyền 600; mỗi mật khẩu gồm 20 ký tự ngẫu nhiên từ `secrets` của Python và hậu tố đáp ứng yêu cầu độ phức tạp của API.
- `./set-passwords.sh`, sau đó `docker compose -f generate-indexer-certs.yml run --rm generator`, sau đó `docker compose up -d`.

### Cài agent (2026-11-10)
- Thêm khóa `GPG-KEY-WAZUH` vào `/usr/share/keyrings/wazuh.gpg` và nguồn `deb [signed-by=...] https://packages.wazuh.com/4.x/apt/ stable main`.
- `WAZUH_MANAGER=127.0.0.1 WAZUH_AGENT_NAME=dell-server apt-get install wazuh-agent=4.14.10-1`, sau đó `apt-mark hold wazuh-agent`.

## Kết quả kiểm tra
### Manager, indexer, dashboard
| Kiểm tra | Kết quả |
|---|---|
| Indexer, user `admin` với mật khẩu mới | 200 |
| Indexer, `admin:SecretPassword` (mặc định) | 401 |
| Indexer, `kibanaro:kibanaro` (user demo) | 401 |
| Trạng thái cụm | `yellow`, 1 node (bình thường với một node vì replica không được cấp phát) |
| API, `wazuh-wui` với mật khẩu mới / mật khẩu mặc định | 200 / 401 |
| Dashboard từ Kali qua Tailscale (`https://100.109.212.65/app/login`) | 200; đăng nhập `admin` với mật khẩu mới: 200 |

### Agent
- `agent_control -l` trên manager: `ID: 001, Name: dell-server, IP: any, Active`. Ảnh: `images/02-agent-active.png` (dashboard, mục Endpoints: active, v4.14.10, nhóm `default`, Ubuntu 26.04.1 LTS).
- Manager đẩy `agent.conf` xuống `/var/ossec/etc/shared/agent.conf` trên host lúc 03:06 UTC; agent tự reload. Sau reload, `ossec.log` của agent có:
  ```
  2026/11/10 03:07:05 wazuh-logcollector: INFO: (1950): Analyzing file: '/var/log/kmam/nginx/access-direct.log'.
  2026/11/10 03:07:06 wazuh-logcollector: INFO: (1950): Analyzing file: '/var/log/kmam/nginx/access-cf.log'.
  2026/11/10 03:07:06 wazuh-logcollector: INFO: (1950): Analyzing file: '/var/log/kmam/app/auth.json'.
  ```

### Luồng log
Gửi một request sai qua mỗi nhánh từ Kali (03:08 UTC), sau đó đọc `alerts.json` trên manager:

| Thời điểm (UTC) | location | rule | level | decoder | srcip |
|---|---|---|---|---|---|
| 03:08:46.337 | `/var/log/kmam/nginx/access-direct.log` | 31101 (Web server 400 error code) | 5 | `web-accesslog` | `100.86.126.91` |
| 03:08:55.055 | `/var/log/kmam/nginx/access-cf.log` | 31101 | 5 | `web-accesslog` | `42.118.107.36` |

- Truy vấn indexer `wazuh-alerts-*` với `rule.id: 31101` và `location` bắt đầu bằng `/var/log/kmam/`: 2 kết quả, mỗi file log một. Ảnh: `images/02-events-web.png` (Threat Hunting, Events; giờ hiển thị theo UTC+7).
- `wazuh-logtest` với dòng cuối của `auth.json`: decoder `json`; trường `user` được ánh xạ sang trường tĩnh `dstuser`, `srcip` giữ tên `srcip`; `msg: login_failed`. Sự kiện chỉ khớp rule 1002 (level 2, "Unknown problem somewhere in the system", do chuỗi chứa "failed"), thấp hơn ngưỡng ghi cảnh báo (level 3), nên chưa có trên dashboard. Rule 100120 ở giai đoạn 3 sẽ xử lý sự kiện này.

### Tài nguyên (`docker stats --no-stream`, 2026-11-10T03:10:59Z, ngay sau khi khởi động, chưa có tải)
```
NAME                           CPU %     MEM USAGE / LIMIT     MEM %
kmam-wazuh-wazuh.manager-1     5.38%     837.1MiB / 14.98GiB   5.46%
kmam-wazuh-wazuh.indexer-1     3.20%     1.476GiB / 14.98GiB   9.85%
kmam-wazuh-wazuh.dashboard-1   0.11%     193.9MiB / 14.98GiB   1.26%
kmam-nginx-1                   0.00%     4.031MiB / 14.98GiB   0.03%
kmam-app-1                     0.00%     2.984MiB / 14.98GiB   0.02%
```
Bộ nhớ host sau khi khởi động: 5,0 GiB đã dùng trên 14 GiB, 9 GiB khả dụng.

Ảnh dashboard được chụp bằng [tools/dashshot.mjs](tools/dashshot.mjs): Chrome headless điều khiển qua DevTools Protocol từ Kali, đăng nhập bằng API `/auth/login`, sau đó mở trang. Lệnh dùng: `DASH_PW=... node docs/notes/tools/dashshot.mjs https://100.109.212.65 <out.png> "<đường dẫn trang>" 60000`; thời gian chờ 60 giây để dashboard chạy xong health check của phiên mới.

## Sự cố và phương án bị loại
- Hiện tượng: lần chạy đầu `set-passwords.sh` ghi chuỗi cảnh báo `WARNING: nor OPENSEARCH_JAVA_HOME nor JAVA_HOME is set` vào vị trí hash. / Nguyên nhân: khi chạy `hash.sh` với entrypoint `bash`, image không đặt `JAVA_HOME`, nên script không tìm thấy `java`. / Cách xử lý: truyền `-e JAVA_HOME=/usr/share/wazuh-indexer/jdk`, bỏ stderr, và kiểm tra kết quả bắt đầu bằng `$2y$`; nếu không, script dừng với lỗi.
- Hiện tượng: khi cài gói agent, bước post-install báo `Error: Timeout was reached`; sau đó apt chờ hook `needrestart` khoảng 10 phút. Khi agent nhận `agent.conf`, systemd báo `wazuh-agent.service: Reload operation timed out` và `Reload failed`. / Nguyên nhân (theo journal): `wazuh-control reload` phải chờ khoảng 30 giây để dừng `wazuh-modulesd`, làm thao tác reload vượt giới hạn thời gian của systemd. / Kết quả: các daemon của agent vẫn khởi động lại đầy đủ và đọc cấu hình mới (xem mục Agent); service ở trạng thái `active (running)`. Chưa xử lý thêm.
- Phương án bị loại: chèn tay đoạn `localfile` vào `ossec.conf` của host (`ossec-agent.conf.snippet` trong kế hoạch ban đầu). Thay bằng `agent.conf` tập trung để cấu hình nằm trong repo và áp dụng không cần sửa file trên host.

## Ghi chú cho báo cáo
- Mục 1.2.2: kiến trúc manager, indexer, dashboard và agent; lý do agent chạy trên host (Active Response cần sửa iptables của host).
- Mục 3.1.2: phiên bản, các thay đổi so với bản Docker gốc (port, mật khẩu, user demo), tài nguyên đo được.
- Mục 3.2.2: luồng log từ ba file tới manager; bảng cảnh báo 31101 của hai nhánh; ánh xạ `user` → `dstuser` của decoder `json` (dùng cho rule E2 ở giai đoạn 3).
