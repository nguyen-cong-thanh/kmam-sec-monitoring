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
- Trên server: <chưa thực hiện>

## Sự cố và phương án bị loại
- Phương án ban đầu chạy `cloudflared` là một container trong cùng file compose, với `set_real_ip_from 172.31.0.0/24` và port 8081 không publish. Phương án bị loại vì `cloudflared` của lab do người thực hiện vận hành riêng trên host (2026-11-10). Thay bằng publish `127.0.0.1:8081` và chỉ tin gateway `172.31.0.1`.

## Ghi chú cho báo cáo
- Mục 2.3.1: sơ đồ hai nhánh truy cập và lý do tách hai file log; vai trò của `set_real_ip_from` khi chỉ tin một địa chỉ nguồn.
- Mục 3.2.1: trích dòng log 401/200 của hai nhánh và một dòng `auth.json`; ảnh bản ghi DNS proxied của `monitor-lab.nguyencongthanh.io.vn`.
