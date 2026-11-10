# 01. Ứng dụng web và Nginx

## Mục tiêu
Dựng ứng dụng đăng nhập trả 401/200, đặt sau Nginx với hai nhánh truy cập (direct qua LAN, cf qua Cloudflare Tunnel), mỗi nhánh ghi một access log riêng, và ứng dụng ghi sự kiện đăng nhập ra `auth.json`. Đây là nguồn log cho các giai đoạn phát hiện và phản ứng.

## Môi trường và phiên bản
- Go: 1.27 (image build `golang:1.27-alpine`; Kali dùng go1.27.3 để chạy test)
- Nginx: `nginx:1.30.6-alpine` (nhánh stable)
- cloudflared: 2026.3.0, chạy như service trên host, cấu hình ngoài repo
- Docker 29.9.3 (Kali), Docker Compose v5.7.0 (server)

## Các bước thực hiện
### Viết ứng dụng đăng nhập (2026-11-10)
- Mã nguồn: [infra/app/main.go](../../infra/app/main.go), test: [infra/app/main_test.go](../../infra/app/main_test.go), image: [infra/app/Dockerfile](../../infra/app/Dockerfile).
- `POST /login` đọc form `username`, `password`; so sánh bằng `crypto/subtle.ConstantTimeCompare` để thời gian phản hồi không phụ thuộc vào số ký tự khớp. Tài khoản hợp lệ lấy từ biến môi trường `APP_USER`, `APP_PASSWORD` trong `.env`.
- Mỗi lần đăng nhập ghi một dòng JSON, ví dụ `{"time":"...","level":"INFO","msg":"login_failed","user":"alice","srcip":"203.0.113.7"}`. Tên trường `srcip` trùng với trường tĩnh của Wazuh, để rule E2 (100121) ở giai đoạn 3 dùng được `different_srcip`.
- IP lấy từ `X-Real-IP` do Nginx đặt; ứng dụng không publish port nên client không gửi trực tiếp header này tới ứng dụng được.
- Image cuối dựa trên `scratch`, chạy với uid 65532 (không phải root).

### Cấu hình Nginx (2026-11-10)
- File: [infra/nginx/nginx.conf](../../infra/nginx/nginx.conf).
- Hai vhost dùng format `combined` có sẵn, để decoder `web-accesslog` của Wazuh đọc được mà không cần decoder riêng.
- Vhost direct (port 80) không bật `real_ip`: `$remote_addr` là địa chỉ TCP thật, nên header giả như `CF-Connecting-IP` hay `X-Forwarded-For` không có tác dụng.
- Vhost cf (port 8081, `server_name monitor-lab.nguyencongthanh.io.vn`) chỉ tin `CF-Connecting-IP` khi kết nối đến từ `172.31.0.1`. `cloudflared` chạy trên host và gọi `127.0.0.1:8081`; kết nối đi qua port publish của Docker nên Nginx thấy địa chỉ nguồn là gateway của mạng `kmam`. Cần xác nhận địa chỉ này khi triển khai (mục Kết quả kiểm tra).

### docker-compose (2026-11-10)
- File: [infra/docker-compose.yml](../../infra/docker-compose.yml).
- Subnet `172.31.0.0/24` được chọn sau khi liệt kê các mạng Docker có sẵn trên server (172.17–172.28/16, 172.30.10.0/24, 192.168.60.0/24 đã dùng).
- Publish port 80 ra LAN; port 8081 chỉ publish trên `127.0.0.1`, máy khác trong LAN không truy cập được.
- Log trên host: `/var/log/kmam/nginx/` (hai access log) và `/var/log/kmam/app/auth.json`.
- `.env` nằm ở gốc repo, được nạp cho `app` bằng `env_file: ../.env`.

## Kết quả kiểm tra
- Cục bộ trên Kali (2026-11-10): `go vet` và `go test ./...` đạt; `docker compose config -q` đạt; `nginx -t` với `nginx:1.30.6-alpine` báo `syntax is ok`; build image ứng dụng thành công.
### Triển khai trên server (2026-11-10)
- Repo tại `/home/thanhnc/developments/master-road/kmam-sec-monitoring`, commit `19c9acb`; `.env` tạo với quyền 600.
- Thư mục log: `install -d -o 65532 -g 65532 /var/log/kmam/app`, `install -d /var/log/kmam/nginx`, `/var/log/kmam` quyền 755.
- `docker compose -f infra/docker-compose.yml up -d --build`: `app` và `nginx` chạy; port `0.0.0.0:80` và `127.0.0.1:8081`; mạng `kmam_kmam` là `172.31.0.0/24`, gateway `172.31.0.1`.
- `ufw status`: `inactive`.

### Kiểm tra (2026-11-10)
Tại thời điểm kiểm tra, Kali không ở trong LAN của server (Kali có địa chỉ `172.20.29.177`), hai máy chỉ kết nối qua Tailscale. Nhánh direct vì vậy được kiểm tra tạm qua IP Tailscale của server (`100.109.212.65`), cùng listener port 80. Kiểm tra từ LAN được để lại (mục Việc còn lại).

| Kiểm tra | Kết quả |
|---|---|
| direct, mật khẩu sai / đúng | 401 / 200 |
| direct, gửi kèm `CF-Connecting-IP`, `X-Real-IP`, `X-Forwarded-For` giả `198.51.100.9` | 401, log ghi `100.86.126.91` (IP thật) |
| direct, `GET /login` | 405 |
| port 8081 từ máy khác | không kết nối được |
| cf qua `127.0.0.1:8081` với `CF-Connecting-IP: 203.0.113.50`, sai / đúng | 401 / 200, log ghi `203.0.113.50` |
| cf qua `127.0.0.1:8081` không có header | log ghi `172.31.0.1`, xác nhận địa chỉ trong `set_real_ip_from` |
| cf qua `https://monitor-lab.nguyencongthanh.io.vn`, sai / đúng | 401 / 200, log ghi `42.118.107.36` (IP công khai của Kali, đối chiếu với `cloudflare.com/cdn-cgi/trace`) |
| cf qua Cloudflare, client tự gửi `CF-Connecting-IP` giả | 403 do Cloudflare trả, request không tới Nginx |
| phân giải `monitor-lab.nguyencongthanh.io.vn` | `104.21.58.79`, `172.67.157.248` (IP của Cloudflare); header `server: cloudflare` |

Trích log:
```
access-direct.log: 100.86.126.91 - - [10/Nov/2026:01:54:10 +0000] "POST /login HTTP/1.1" 401 20 "-" "curl/8.22.0"
access-cf.log:     42.118.107.36 - - [10/Nov/2026:02:04:44 +0000] "POST /login HTTP/1.1" 401 20 "-" "curl/8.22.0"
auth.json:         {"time":"2026-11-10T02:04:44.984069337Z","level":"INFO","msg":"login_failed","user":"admin","srcip":"42.118.107.36"}
```

Ảnh chụp (output thật của lệnh trên Kali, hiển thị lại dạng terminal bằng Chrome headless; mật khẩu trong lệnh `curl` được thay bằng `<redacted>`):
- `images/01-log-direct.png`: 401/200 và dòng log nhánh direct;
- `images/01-log-cf.png`: 401/200 và dòng log nhánh cf;
- `images/01-cf-proxied.png`: bằng chứng bản ghi đi qua proxy Cloudflare (thay cho ảnh dashboard DNS, vì phiên làm việc không truy cập được dashboard Cloudflare).

## Việc còn lại
- [ ] Khi Kali ở trong LAN của server: từ `192.168.1.183` gửi request sai/đúng tới `http://192.168.1.142/login`, xác nhận 401/200 và `access-direct.log`, `auth.json` ghi `192.168.1.183`. Chụp lại `images/01-log-direct.png` từ LAN.

## Sự cố và phương án bị loại
- Hiện tượng: sau khi tạo thư mục log, `ls /var/log/kmam/*` báo lỗi quyền. / Nguyên nhân: lệnh chạy với `umask 077` (đặt để tạo `.env`), nên `install -d` tạo thư mục cha `/var/log/kmam` với quyền 700. / Cách xử lý: `chmod 755 /var/log/kmam`.
- Phương án ban đầu chạy `cloudflared` là một container trong cùng file compose, với `set_real_ip_from 172.31.0.0/24` và port 8081 không publish. Phương án bị loại vì `cloudflared` của lab do người thực hiện vận hành riêng trên host (2026-11-10). Thay bằng publish `127.0.0.1:8081` và chỉ tin gateway `172.31.0.1`.

## Ghi chú cho báo cáo
- Mục 2.3.1: sơ đồ hai nhánh truy cập và lý do tách hai file log; vai trò của `set_real_ip_from` khi chỉ tin một địa chỉ nguồn.
- Mục 3.2.1: trích dòng log 401/200 của hai nhánh và một dòng `auth.json`; ảnh bản ghi DNS proxied của `monitor-lab.nguyencongthanh.io.vn`.
