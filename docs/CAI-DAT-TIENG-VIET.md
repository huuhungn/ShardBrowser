# Hướng dẫn cài đặt ShardX Launcher (tiếng Việt)

Dành cho người mới dùng lần đầu. Toàn bộ số liệu và thông báo lỗi trong tài liệu
này đều lấy từ bản v2.2.0 thực tế.

## 1. Tải bản cài đặt

Vào trang [GitHub Releases](https://github.com/huuhungn/ShardBrowser/releases/latest) và tải tệp theo hệ điều hành:

| Hệ điều hành | Tệp nên tải | Ghi chú |
| --- | --- | --- |
| Windows | `ShardX.Launcher_2.2.0_x64-setup.exe` | Bản cài đặt thông thường, có tự động cập nhật |
| Windows (không cài đặt) | `ShardX-Launcher-portable-win-x64.exe` | Chạy thẳng, không ghi vào máy |
| macOS (Apple Silicon) | `.dmg` bản `aarch64` | Chỉ có đến bản 2.11.1; từ 2.12.0 không phát hành bản macOS |
| Linux | `.AppImage` hoặc `.deb` | |

### Kiểm tra tệp tải về (khuyến nghị)

Mỗi bản phát hành kèm `SHA256SUMS.txt`. So khớp để chắc chắn tệp không bị hỏng
hoặc bị thay giữa đường:

```bash
# Windows (Git Bash) — chú ý dấu "<", không truyền tên tệp trực tiếp
sha256sum < ShardX.Launcher_2.2.0_x64-setup.exe

# macOS / Linux
shasum -a 256 ShardX.Launcher_2.2.0_x64-setup.exe
```

Đối chiếu chuỗi in ra với dòng tương ứng trong `SHA256SUMS.txt`.

## 2. Cảnh báo của hệ điều hành khi mở lần đầu

Bản phát hành **không mua chữ ký số** (Authenticode trên Windows, Apple
Developer ID trên macOS), nên hệ điều hành sẽ cảnh báo ở lần chạy đầu. Đây là
điều đã biết trước, không phải dấu hiệu tệp bị lỗi — hãy kiểm tra SHA-256 ở
bước trên nếu bạn muốn chắc chắn.

* **Windows:** hiện bảng *"Windows protected your PC"*. Bấm **More info** →
  **Run anyway**. Các lần sau không hỏi lại.
* **macOS:** Gatekeeper báo không xác minh được, hoặc báo ứng dụng "bị hỏng".
  Gỡ cờ cách ly một lần trong Terminal:
  ```bash
  xattr -dr com.apple.quarantine "/Applications/ShardX Launcher.app"
  ```
* **Linux (AppImage):** cấp quyền chạy trước:
  ```bash
  chmod +x ShardX-Launcher.AppImage && ./ShardX-Launcher.AppImage
  ```

### Linux cần thêm thư viện hệ thống

Nhân Chromium đi kèm cần `unzip` và các thư viện Chromium thường liên kết:

```bash
sudo apt install -y \
  unzip ca-certificates fonts-liberation \
  libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 libcups2 \
  libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 libxrandr2 \
  libgbm1 libpango-1.0-0 libcairo2 libasound2 libxshmfence1
```

## 3. Lần chạy đầu tiên

Ứng dụng tự tải nhân trình duyệt đã vá (~150 MB), Widevine (~16 MB) và thư viện
fingerprint (~470 KB). Hãy để mạng ổn định trong lúc này.

Dữ liệu được đặt tại:

* Windows: `%APPDATA%\shardx-launcher\`
* macOS: `~/Library/Application Support/shardx-launcher/`
* Linux: `~/.config/shardx-launcher/`

Sau khi tải xong là có thể gắn proxy và mở hồ sơ (profile) đầu tiên.

> **Lưu ý khi cài đè bản cũ:** thư mục dữ liệu ở trên **không** bị xoá khi cài
> bản mới, nên hồ sơ và fingerprint vẫn còn. Dù vậy, nên sao lưu thư mục này
> trước khi nâng cấp nếu bạn đang có dữ liệu quan trọng.

## 4. Kết nối với trợ lý AI (MCP)

ShardX Launcher đi kèm một máy chủ MCP để trợ lý AI điều khiển trình duyệt.
Từ v2.2.0, **Hermes là host chính**.

1. Mở **Settings** trong ứng dụng, tìm thẻ **MCP**.
2. Bấm **Check Hermes registration** — nút chính, nằm đầu thẻ.
3. Nếu báo thiếu tệp MCP, bấm nút tải/sửa để lấy đúng bộ tệp cho phiên bản
   launcher đang chạy.

Kiểm tra lại từ dòng lệnh:

```bash
hermes config get mcp_servers.shardbrowser
```

Các host khác (ví dụ Codex) nằm trong mục **Advanced** của cùng thẻ đó — mở ra
khi cần, kể cả để lấy lệnh sửa chữa.

## 5. Cập nhật ứng dụng

Ứng dụng tự kiểm tra bản mới và tải qua kênh cập nhật có ký số riêng (khác với
chữ ký Authenticode nói ở mục 2 — kênh này **luôn** được xác minh bằng khoá
nhúng sẵn trong ứng dụng, nên bản cập nhật giả mạo sẽ bị từ chối).

Muốn cập nhật thủ công thì tải bản mới nhất từ Releases và cài đè lên bản cũ.

## 6. Gặp sự cố

* **Tải nhân trình duyệt lỗi giữa chừng:** mở lại ứng dụng, quá trình tải sẽ
  tiếp tục. Kiểm tra tường lửa/proxy nếu vẫn lỗi.
* **Không cài được nhân mới:** hãy đóng hết hồ sơ đang mở. Từ v2.1.1, ứng dụng
  cố ý dừng lại và liệt kê hồ sơ đang giữ nhân thay vì ghi đè nửa chừng.
* **Muốn dùng thư mục MCP có sẵn:** trong Settings chọn **Use existing MCP
  folder** thay vì tải bản mới.
