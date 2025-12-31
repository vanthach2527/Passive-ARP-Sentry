# 🛡️ Thach Sensor - Network Intelligence Unit

> **Advanced ARP Reconnaissance & Device Fingerprinting System**
> *Developed by Thach Sensor*

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python)
![Security](https://img.shields.io/badge/Security-ARP%20Recon-red?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey?style=for-the-badge)

## 📜 Giới thiệu (Overview)

**Thach Sensor V18.5** là hệ thống giám sát an ninh mạng cục bộ (LAN) chuyên sâu, được thiết kế theo tư duy **"Zero Trust"**. Hệ thống sử dụng kỹ thuật **Passive ARP Sniffing** kết hợp với phân tích đa luồng để phát hiện, định danh và cảnh báo xâm nhập theo thời gian thực.

Điểm đặc biệt của phiên bản này là khả năng **"Smart Persistence"** (Ghi nhớ thông minh) - giúp phân biệt giữa thiết bị quen thuộc và mối đe dọa mới, loại bỏ hoàn toàn việc spam cảnh báo giả.

## 🚀 Điểm nổi bật về Kỹ thuật (Technical Highlights)

Phiên bản V18.5 mang đến những cải tiến cốt lõi về thuật toán so với các phiên bản trước:

### 1. Dual-Layer Logic (Cơ chế Kép)
Code tách biệt hoàn toàn hai luồng xử lý:
* **Session View (Console):** Hiển thị *toàn bộ* thiết bị đang online ngay lập tức để Administrator dễ dàng giám sát trạng thái mạng.
* **Alert Logic (Telegram):** Chỉ gửi cảnh báo khi phát hiện thiết bị *chưa từng xuất hiện* trong cơ sở dữ liệu lịch sử (`detected_macs.json`).

### 2. Smart Persistence Engine (Bộ nhớ thông minh)
Hệ thống tự động duy trì một tệp JSON cục bộ làm "Brain" (Bộ não).
* **Input:** Gói tin ARP từ mạng.
* **Process:** So khớp MAC Address với dữ liệu cũ.
* **Output:** Quyết định im lặng (nếu là máy cũ) hoặc Báo động đỏ (nếu là máy lạ).

### 3. Multi-threaded Fingerprinting (Đa luồng)
Sử dụng `ThreadPoolExecutor` với 30 workers hoạt động song song.
* Thay vì quét tuần tự từng máy (gây chậm), hệ thống quét cổng dịch vụ (Port 80, 443, 554...) của 30 thiết bị cùng lúc.
* Tốc độ nhận diện Vendor và Loại thiết bị (Camera/Apple/PC) nhanh gấp **5 lần** so với đơn luồng.

### 4. Cyberpunk Interface (UI)
Giao diện dòng lệnh (CLI) được thiết kế lại với phong cách Cyberpunk, hỗ trợ hiển thị Icon trực quan cho từng loại thiết bị ( Apple, 📷 Camera, ❖ Windows).

---

## 🛠️ Hướng dẫn Cài đặt (Installation)

### Yêu cầu hệ thống (Prerequisites)
* Python 3.8 trở lên.
* **Npcap** (Đối với Windows): Bắt buộc để bắt gói tin. Tải tại [npcap.com](https://npcap.com/) (Chọn chế độ *"WinPcap API-compatible Mode"*).

### Bước 1: Clone dự án
```bash
git clone [https://github.com/vanthach2527/Thach-Sensor-V18.git](https://github.com/USERNAME-CUA-BAN/Thach-Sensor-V18.git)
cd Thach-Sensor-V18