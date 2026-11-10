# Kế hoạch triển khai

Tài liệu này chi tiết hóa phần triển khai của [plan.md](plan.md): thứ tự thực hiện, sản phẩm trong repo, cách kiểm tra từng bước và quy ước ghi chú phục vụ viết báo cáo.

## 1. Bối cảnh và các quyết định đã chốt

| Hạng mục | Quyết định |
|---|---|
| Máy client | Máy Kali của nhóm: làm máy trạm và máy tấn công; LAN 192.168.1.183 |
| Máy server | Ubuntu 26.04.1 LTS, 4 CPU, 14 GiB RAM, 150 GB đĩa trống; LAN 192.168.1.142, nằm sau NAT của mạng gia đình; chạy Nginx, ứng dụng đăng nhập, Wazuh manager và Wazuh agent |
| Đường quản trị | SSH qua Tailscale, tách khỏi địa chỉ LAN dùng để tấn công |
| Ràng buộc | Máy chủ đang chạy container của các dự án khác (các port 1883, 3080, 8080, 8883, 32768); được phép dừng các container này khi cần tài nguyên hoặc port. Port 80 và 443 còn trống; ufw đang bật |
| Đồng bộ mã | Hai máy dùng chung repo git; server cập nhật bằng `git pull` |
| Reverse proxy | Nginx |
| Cloudflare | Zone `nguyencongthanh.io.vn`; lab chỉ dùng subdomain `monitor-lab.nguyencongthanh.io.vn`, vì zone còn phục vụ các dịch vụ khác |
| Phạm vi | Làm đầy đủ phần bắt buộc và các phần mở rộng E1–E5; không ràng buộc theo hạn nộp |

## 2. Kiến trúc triển khai

```
Client (Kali)                         Server
─────────────                         ──────────────────────────────────────────────
attack/*  ── nhánh 1: LAN ──────────────▶ Nginx :80 (direct) ─────┐
          ── nhánh 2: Internet          cloudflared ──▶ Nginx    ├─▶ app (Go) ── auth.json
             → Cloudflare ────────────▶ (tunnel)   :8081 (cf)│
                                      access-direct.log ◀──────┤
                                      access-cf.log     ◀──────┘
                                              │
                                      Wazuh agent (cài trên host)
                                              │            ▲
                                              ▼            │ Active Response
                                      Wazuh manager (Docker single-node)
                                              │
                                      ├─ firewall-drop  → iptables trên host (nhánh 1)
                                      └─ cloudflare-ban → Cloudflare API     (nhánh 2)
```

Các lựa chọn thiết kế:

1. **Tách hai nhánh bằng hai port và hai file log.**
   - Port 80 publish ra LAN, phục vụ nhánh direct.
   - Port 8081 chỉ publish trên `127.0.0.1`; `cloudflared` chạy như service trên host (quản lý riêng, ngoài repo) gọi tới, phục vụ nhánh cf.
   - Máy chủ nằm sau NAT, không có port forwarding, nên nhánh Cloudflare dùng Cloudflare Tunnel.

   Mỗi rule tương quan gắn với một file log qua thẻ `<location>`. Nhờ đó Active Response của nhánh nào chỉ chạy cho nhánh đó, và số liệu hai nhánh không lẫn vào nhau.
2. **Wazuh agent cài trực tiếp trên host, không chạy trong container.** `firewall-drop` phải thay đổi iptables của host. Nếu agent chạy trong container, lệnh chặn chỉ có tác dụng trong network namespace của container đó.
3. **Ứng dụng đăng nhập tự viết bằng Go.** Ứng dụng chỉ dùng thư viện chuẩn (`net/http`, `log/slog`) và được build thành một binary trong image Docker nhiều giai đoạn, nên máy chủ không cần cài Go. Ứng dụng trả về 401 khi đăng nhập sai và 200 khi đúng. Ngoài ra, ứng dụng ghi sự kiện đăng nhập dạng JSON (`msg` là `login_failed` hoặc `login_success`, `user`, `srcip`) ra `auth.json`, phục vụ phát hiện tấn công phân tán theo tài khoản (E2), vì access log của Nginx không chứa username.
4. **Bí mật không đưa vào repo.** API token Cloudflare và mật khẩu Wazuh để trong `.env` (khai báo trong `.gitignore`). Repo chỉ chứa `.env.example`.
5. **Tách phòng thủ và tấn công thành hai repo riêng.** Công cụ sinh tải tấn công đặt ở một repo độc lập, không nằm trong repo phòng thủ. Nhờ đó, phiên làm việc xây dựng phần phòng thủ không nạp nội dung tấn công và giữ nguyên năng lực mô hình. Hai repo trao đổi dữ liệu một chiều: repo tấn công sinh ra `attack.csv`, người thực hiện chép vào `experiments/results/` của repo phòng thủ để phân tích. Việc phân tích (`metrics.py`) thuộc repo phòng thủ, vì chỉ đọc số liệu, không sinh tải.

## 3. Cấu trúc hai repo

### Repo phòng thủ (`kmam-sec-monitoring`, repo hiện tại)

```
infra/
  docker-compose.yml        # nginx + app
  nginx/nginx.conf          # log_format, vhost direct và cf, real_ip, limit_req (E3)
  app/                      # ứng dụng đăng nhập Go: main.go, main_test.go, Dockerfile
  wazuh/                    # cấu hình chạy Wazuh manager single-node
wazuh/
  rules/local_rules.xml
  decoders/local_decoder.xml   # chỉ tạo khi decoder có sẵn không đáp ứng
  ossec-manager.conf.snippet   # command, active-response, white_list
  ossec-agent.conf.snippet     # localfile
  integrations/                # custom-telegram (E4)
  tests/                       # log mẫu và script chạy wazuh-logtest
active-response/
  cloudflare-ban.py
  test_cloudflare_ban.py
experiments/
  metrics.py                # tính chỉ số từ attack.csv và alerts
  results/                  # số liệu thô theo kịch bản và lần chạy
docs/
  plan.md, deployment-plan.md
  notes/                    # nhật ký triển khai (mục 5)
```

### Repo tấn công (độc lập)

Cấu trúc repo này được mô tả trong tài liệu riêng của nó. Repo phòng thủ chỉ nhận đầu ra `attack.csv` từ nó; mọi chi tiết về công cụ sinh tải nằm ngoài phạm vi repo phòng thủ.

## 4. Các giai đoạn triển khai

Mỗi giai đoạn chỉ kết thúc khi phần kiểm tra đạt và file ghi chú tương ứng (mục 5) đã được cập nhật.

### Giai đoạn 0. Chuẩn bị môi trường

- **Server:** đã có sẵn Docker Compose v5.7.0, git, chrony, cloudflared và Tailscale. Cần thêm:
  - clone repo;
  - tạo `.env` từ `.env.example`.
- **Client:** cài hydra, python3 (thư viện requests), chrony nếu chưa có.
- **Đồng bộ thời gian:** đồng bộ NTP trên cả hai máy. Các chỉ số thời gian được tính trên đồng hồ của cả hai máy, nên độ lệch đồng hồ ảnh hưởng trực tiếp đến số liệu.
- **Đường quản trị:** SSH qua Tailscale (alias `dell-server`). IP Tailscale của client được đưa vào `white_list`. IP LAN của client vẫn bị chặn bình thường khi tấn công.
- **Kiểm tra:**
  - `chronyc tracking` trên hai máy cho độ lệch dưới 50 ms;
  - SSH vào server qua đường quản trị.
- **Ghi chú:** `docs/notes/00-moi-truong.md`, phục vụ mục 3.1 của báo cáo.

### Giai đoạn 1. Ứng dụng web và Nginx

- **`infra/app`:** viết ứng dụng Go với `POST /login`, trả 401 khi sai và 200 khi đúng, đồng thời ghi `auth.json` bằng `slog.JSONHandler`.
  - IP client trong `auth.json` lấy từ header `X-Real-IP` do Nginx đặt. Ứng dụng chỉ nhận lưu lượng từ Nginx qua mạng nội bộ Docker, không publish port ra ngoài, nên client không giả mạo được header này.
  - `main_test.go` kiểm tra hai trường hợp 401/200 và nội dung dòng log JSON.
- **`infra/nginx/nginx.conf`:**
  - dùng log format `combined` để tận dụng decoder `web-accesslog` có sẵn;
  - vhost `direct` ghi `access-direct.log`;
  - vhost `cf` (port 8081) ghi `access-cf.log`, cấu hình `real_ip_header CF-Connecting-IP`. `set_real_ip_from` trỏ tới gateway `172.31.0.1` của mạng Docker. Vì lưu lượng đi qua tunnel và `cloudflared` chạy trên host, kết nối tới Nginx xuất phát từ gateway này, không phải từ dải IP của Cloudflare.
- **`infra/docker-compose.yml`:** chạy nginx và app.
  - Bind-mount thư mục log ra `/var/log/kmam/` trên host: `nginx/` chứa hai access log, `app/` chứa `auth.json` (thư mục `app/` thuộc uid 65532, là user chạy ứng dụng trong container).
  - Khai báo subnet cố định `172.31.0.0/24` cho mạng nội bộ (không trùng các mạng Docker có sẵn trên máy chủ).
  - Publish port 80 ra LAN và port 8081 chỉ trên `127.0.0.1`.
- **Cloudflare:** `cloudflared` trên host được người thực hiện cấu hình riêng, ngoài repo. Hostname `monitor-lab.nguyencongthanh.io.vn` trỏ tới `http://localhost:8081`.
- **Kiểm tra:**
  - `curl` với mật khẩu sai trả 401, mật khẩu đúng trả 200, qua cả hai nhánh;
  - trường IP trong log là IP thật của client, không phải IP gateway của Docker hay IP của Cloudflare.
- **Ghi chú:** `docs/notes/01-web-nginx.md`, phục vụ mục 2.3.1 và 3.2.1.

### Giai đoạn 2. Wazuh manager và agent

- **Manager:** dựng Wazuh manager bằng bản Docker single-node chính thức, ghim một phiên bản cụ thể. Mount `wazuh/rules` và `wazuh/decoders` vào container.
- **Agent:** cài agent trên host và đăng ký với manager.
- **Nguồn log của agent:**
  - `localfile` cho hai access log;
  - `auth.json` với `log_format` là `json`.
- **Kiểm tra:**
  - agent ở trạng thái active;
  - sự kiện từ cả ba file log xuất hiện trên dashboard;
  - đo RAM/CPU của manager bằng `docker stats` và lưu lại.
- **Ghi chú:** `docs/notes/02-wazuh.md`, phục vụ mục 1.2.2, 3.1.2 và 3.2.2.

### Giai đoạn 3. Decoder và rule phát hiện

Trong `wazuh/rules/local_rules.xml`, ID từ 100100:

| ID | Nội dung | Level | MITRE |
|---|---|---|---|
| 100100 / 100110 | Một request `/login` trả 401 (nhánh direct / cf) | 5 | – |
| 100101 / 100111 | 10 lần trong 60 giây, cùng IP nguồn (nhánh direct / cf) | 10 | T1110.001 |
| 100105 | 200 trên `/login` sau 100101 hoặc 100111, cùng IP (E1) | 13 | T1110 |
| 100120 | Sự kiện `login_failed` từ `auth.json` | 3 | – |
| 100121 | Cùng username, nhiều IP khác nhau trong cửa sổ thời gian (E2) | 10 | T1110.003 |

- **Kiểm tra tự động:** `wazuh/tests/` chứa các dòng log mẫu và một script đưa chúng qua `wazuh-logtest`. Script xác nhận từng dòng khớp đúng rule ID mong đợi.
- **Ngưỡng:** mỗi lần thay ngưỡng để thực nghiệm phải ứng với một commit riêng. Hash của commit đó được ghi vào kết quả lần chạy.
- **Ghi chú:** `docs/notes/03-rules.md`, phục vụ mục 2.4 và 3.2.2.

### Giai đoạn 4. Active Response bằng iptables

- **Cấu hình manager:**
  - `active-response` dùng lệnh `firewall-drop`, `location` là `local`, `rules_id` là 100101, timeout 600 giây;
  - `white_list` chứa IP quản trị.
- **Kiểm tra:**
  - client gửi một loạt request sai và sau đó bị chặn kết nối;
  - `iptables -S` trên host có luật DROP cho IP client;
  - luật tự gỡ sau khi hết timeout;
  - đối chiếu với `active-responses.log`.
- **Điểm cần xác minh bằng thực nghiệm:**
  - Lưu lượng tới port do Docker publish đi qua chuỗi FORWARD/DOCKER thay vì INPUT, và không chịu tác động của ufw. Cần kiểm tra luật của `firewall-drop` có chặn được lưu lượng này không.
  - Ubuntu 26.04 dùng iptables với backend nft. Cần kiểm tra luật do `firewall-drop` thêm vào có hiển thị và có hiệu lực cùng các luật của Docker không.
  - Kết quả của cả hai điểm, kể cả khi không chặn được, đều được ghi lại kèm cách xử lý.
- **Ảnh hưởng tới dịch vụ khác:** trong thời gian bị chặn, IP LAN của client cũng không truy cập được các dịch vụ khác trên máy chủ. Đây là hành vi mong đợi. Timeout được đặt ngắn trong lúc thử nghiệm.
- **Ghi chú:** `docs/notes/04-ar-iptables.md`, phục vụ mục 2.5.1, 2.5.3 và 3.2.3.

### Giai đoạn 5. Active Response bằng Cloudflare API

- **Cơ chế chặn:** dùng Custom List `kmam_banned` và một WAF custom rule. Rule có biểu thức `http.host eq "monitor-lab.nguyencongthanh.io.vn" and ip.src in $kmam_banned` và hành động Block. Rule được tạo một lần khi cấu hình; Active Response chỉ thay đổi nội dung list. Nhờ đó các subdomain khác của zone không bị ảnh hưởng.
- **API token:** quyền Account / Account Filter Lists / Edit. Token lưu trên host (đọc từ file trong `/var/ossec/etc/`), không đưa vào repo.
- **Hạn mức:** cần xác minh hạn mức số list và số phần tử của gói Free trước khi triển khai.
- **`active-response/cloudflare-ban.py`:**
  - đọc JSON từ stdin và thực hiện giao thức `check_keys`;
  - lệnh `add` thêm IP vào `kmam_banned`, ghi rule ID và thời điểm vào trường comment của phần tử;
  - lệnh `delete` tìm và xóa phần tử tương ứng;
  - ghi log vào `active-responses.log`.
- **Triển khai và cấu hình:**
  - script đặt tại `/var/ossec/active-response/bin/`, chủ sở hữu `root:wazuh`, quyền 750;
  - manager khai báo `command` và `active-response` cho `rules_id` 100111.
- **Kiểm tra:**
  - `test_cloudflare_ban.py` kiểm tra phần phân tích thông điệp và tạo request khi gọi API giả lập;
  - kiểm tra thủ công bằng `echo '<json>' | cloudflare-ban.py`;
  - chạy đầy đủ một vòng: client qua `monitor-lab.nguyencongthanh.io.vn` nhận phản hồi chặn từ Cloudflare, IP xuất hiện trong list trên dashboard, IP tự được xóa khỏi list sau timeout;
  - đo độ trễ từ lúc gọi API đến lúc lệnh chặn có hiệu lực.
- **Ghi chú:** `docs/notes/05-ar-cloudflare.md`, phục vụ mục 2.5.2 và 3.2.3.

### Giai đoạn 6. Các phần mở rộng

- **E1, E2:** đã làm ở giai đoạn 3. Giai đoạn này kiểm thử chúng bằng lưu lượng thật.
- **E3:** bật `limit_req` cho `/login` (trả 429) dưới dạng một cấu hình riêng. Chạy lại S1 để so sánh chặn tại proxy với chặn qua SIEM. Cần ghi nhận rằng 429 làm giảm số dòng 401 mà rule đếm được.
- **E4:** viết integration `custom-telegram` gửi cảnh báo từ level 10.
- **E5:** gắn thẻ `<mitre>` vào rule, kiểm tra trên mô-đun MITRE ATT&CK của dashboard.
- **Ghi chú:** `docs/notes/06-mo-rong.md`, phục vụ mục 1.4, 2.4.4 và 3.4.

### Giai đoạn 7. Thực nghiệm và thu số liệu

- **Công cụ sinh tải:** thuộc repo tấn công độc lập (mục 2, lựa chọn 5). Công cụ nhận tham số kịch bản, URL, tốc độ request, danh sách mật khẩu, và ghi `attack.csv` từng request gồm thời điểm, mã trạng thái, độ trễ, lỗi kết nối. Hydra dùng song song để minh họa công cụ thực tế; số liệu định lượng lấy từ `attack.csv`.
- **Nguồn IP:** kịch bản S5 dùng phương án nhiều IP ở V3 (mục 6).
- **Luồng dữ liệu:** sau mỗi lần chạy, chép `attack.csv` từ repo tấn công vào `experiments/results/` của repo này để phân tích.
- **Kịch bản:** S1–S6 theo [plan.md](plan.md) mục 6. Mỗi kịch bản chạy 5 lần. Kịch bản S1 chạy thêm với các ngưỡng 5, 10 và 20 lần trong 60 giây.
- **Kết quả mỗi lần chạy:** lưu tại `experiments/results/<kich-ban>/<thoi-diem>/`, gồm:
  - `attack.csv`;
  - đoạn trích `alerts.json`;
  - đoạn trích `active-responses.log`;
  - `config.txt` (commit hash, ngưỡng, timeout);
  - `metrics.json`.
- **`experiments/metrics.py`:** tính thời gian đến cảnh báo, thời gian đến khi bị chặn và số request lọt qua, chỉ từ các file thô trên. Báo cáo không dùng số liệu nào không có file nguồn.
- **Ghi chú:** `docs/notes/07-thuc-nghiem.md`, phục vụ mục 3.3 và 3.4.

### Giai đoạn 8. Viết báo cáo

Viết từng mục theo đề cương, lấy nội dung từ `docs/notes/` và số liệu từ `experiments/results/`. Bước này được lập kế hoạch riêng khi bắt đầu.

## 5. Quy ước ghi chú triển khai

### 5.1. Nguyên tắc

1. Mỗi giai đoạn có một file `docs/notes/NN-<ten>.md`.
2. Ghi ngay khi làm xong từng bước, không ghi bù vào cuối giai đoạn.
3. File ghi chú được commit cùng mã nguồn và cấu hình của bước đó.
4. Không chép lại nội dung file cấu hình vào ghi chú. Ghi chú dẫn tới file trong repo và chỉ trích phần cần giải thích.
5. Ghi lại cả phương án đã thử nhưng bị loại, kèm lý do và số liệu. Báo cáo cần phần này để trình bày quá trình lựa chọn giải pháp.
6. Mọi con số phải dẫn được về một file thô trong `experiments/results/` hoặc một output đã lưu.
7. Ảnh chụp màn hình lưu tại `docs/notes/images/NN-<mo-ta>.png`. Thư mục `docs/images/` được dành cho công cụ build báo cáo.

### 5.2. Mẫu file ghi chú

```markdown
# NN. <Tên giai đoạn>

## Mục tiêu
<một đoạn ngắn>

## Môi trường và phiên bản
- <phần mềm>: <phiên bản chính xác>

## Các bước thực hiện
### <Bước> (YYYY-MM-DD, người thực hiện)
- Lệnh / cấu hình: <dẫn tới file trong repo, trích dòng cần giải thích>
- Lý do chọn cách này: <...>

## Kết quả kiểm tra
- <output đã trích, đường dẫn ảnh chụp, đường dẫn file kết quả>

## Sự cố và phương án bị loại
- Hiện tượng: <...> / Nguyên nhân: <...> / Cách xử lý: <...>

## Ghi chú cho báo cáo
- Mục <x.y.z>: <ý cần viết, hình hoặc bảng cần có>
```

### 5.3. Ảnh chụp cần thu thập

| Giai đoạn | Ảnh chụp |
|---|---|
| 1 | Dòng log 401/200 của hai nhánh; bản ghi DNS proxied trên Cloudflare |
| 2 | Agent active; sự kiện web trên dashboard |
| 3 | Output của `wazuh-logtest` cho rule 100101 và 100105 |
| 4 | Cảnh báo kích hoạt AR; `iptables -S` trước, trong và sau khi chặn; client bị từ chối kết nối |
| 5 | Custom List và sự kiện của WAF custom rule trên Cloudflare dashboard; trang chặn của Cloudflare phía client |
| 6 | Tin nhắn Telegram; mô-đun MITRE ATT&CK trên dashboard |
| 7 | Dashboard trong lúc chạy kịch bản; biểu đồ tổng hợp được dựng từ số liệu |

## 6. Vấn đề còn mở

Đã giải quyết:

- **V1. IP quản trị trùng với IP tấn công.** Quản trị qua Tailscale; tấn công qua LAN (nhánh 1) và Internet (nhánh 2).
- **V2. Thông tin máy chủ.** Đã ghi ở mục 1.
- **V4. Phạm vi chặn trên Cloudflare.** Dùng Custom List kết hợp một WAF custom rule giới hạn theo hostname của lab, vì tên miền còn phục vụ các dịch vụ khác. Không dùng IP Access Rule cấp zone.
- **V5. Tên miền.** Lab dùng `monitor-lab.nguyencongthanh.io.vn`, không thay đổi các bản ghi khác của zone.

Còn mở:

- **V3. Nguồn nhiều IP cho kịch bản S5.** Tạm giả định nhóm có 3 máy với 3 IP công khai khác nhau; phương án cụ thể trao đổi sau. Các hướng đã cân nhắc: điện thoại nhiều nhà mạng, nhiều laptop, IP phụ trên LAN cho nhánh direct, và phát lại log tổng hợp để đánh giá riêng phần phát hiện.
  - Lưu ý khi chốt: CGNAT và IPv6 của mạng di động làm IP thay đổi giữa các lần chạy, nên mỗi lần chạy phải ghi lại IP thực tế xuất hiện trong `access-cf.log`.
  - Giả mạo header `X-Forwarded-For` hoặc `CF-Connecting-IP` không phải cách giả lập hợp lệ; Nginx chỉ tin `CF-Connecting-IP` khi kết nối đến từ gateway của mạng Docker, nơi lưu lượng của `cloudflared` đi vào. Có thể dùng việc giả mạo này làm một kịch bản kiểm chứng cấu hình real IP.
