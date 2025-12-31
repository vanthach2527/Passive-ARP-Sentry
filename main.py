# -----------------------------------------------------------------------------
# Project: Thach Sensor - Network Intelligence Unit
# Version: 18.5 Ultimate Edition
# Author:  Thach Sensor (https://github.com/vanthach2527)
# Date:    December 2025
# License: MIT License
# Description: Advanced ARP Reconnaissance & Device Fingerprinting Tool
# -----------------------------------------------------------------------------

import sys
import os
import time
import threading
import socket
import requests
import logging
import ipaddress
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Back, Style, init

# ================= CẤU HÌNH (CONFIGURATION) =================
# LƯU Ý QUAN TRỌNG:
# 1. Khi chạy trên máy tính của bạn: Điền Token thật vào thay cho chữ "YOUR_..."
# 2. Khi up lên GitHub: Hãy để nguyên chữ "YOUR_..." để không bị lộ mật khẩu.
CONFIG = {
    "TG_TOKEN": os.environ.get("TG_TOKEN", "YOUR_BOT_TOKEN_HERE"), 
    "CHAT_ID": os.environ.get("CHAT_ID", "YOUR_CHAT_ID_HERE"),
    
    "VENDOR_API": "https://api.macvendors.co/",
    "SCAN_INTERVAL": 2,       # Giây (Tốc độ quét)
    "WORKERS": 50,            # Số luồng xử lý song song
    
    # Tên card mạng (Thay đổi tùy theo máy: 'Wi-Fi', 'Ethernet', v.v.)
    "INTERFACE_NAME": "Wi-Fi", 
    
    "PERSIST_FILE": "detected_macs.json",
    "ALERT_COOLDOWN": 1.5,    # Giây (Chống spam tin nhắn)
}

# ================= KHỞI TẠO (INITIALIZATION) =================
init(autoreset=True)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

try:
    import telebot
    import scapy.all as scapy
    # Cấu hình interface cho Scapy (nếu cần thiết)
    # scapy.conf.iface = CONFIG["INTERFACE_NAME"] 
except ImportError:
    sys.exit(f"{Fore.RED}❌ Missing libraries. Run: pip install -r requirements.txt{Style.RESET_ALL}")

# ----------------- MODULE: NETWORK MANAGER -----------------
class NetworkManager:
    @staticmethod
    def get_local_ip():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    @staticmethod
    def get_subnet(ip):
        try:
            return str(ipaddress.ip_network(f"{ip}/24", strict=False))
        except Exception:
            return f"{ip}/24"

# ----------------- MODULE: FINGERPRINTING -----------------
class DeviceFingerprinter:
    def __init__(self, workers=20):
        self.vendor_cache = {}
        # Các cổng đặc trưng để nhận diện loại thiết bị
        self.ports_map = {
            62078: " Apple Mobile",
            5353:  " Bonjour Protocol",
            80:    "🌐 HTTP Interface",
            443:   "🔒 SSL/TLS Service",
            554:   "📷 RTSP Stream (Cam)",
            22:    "🐧 SSH Terminal",
            8080:  "⚙️ Web Service",
            3389:  "💻 Remote Desktop",
            8000:  "📺 Media Host",
            23:    "📟 Telnet (IoT)"
        }
        self.executor = ThreadPoolExecutor(max_workers=workers)

    def get_vendor(self, mac):
        if not mac: return "Unknown Vendor"
        if mac in self.vendor_cache: return self.vendor_cache[mac]
        try:
            resp = requests.get(CONFIG["VENDOR_API"] + mac, timeout=1.5)
            vendor = resp.text.strip() if resp.status_code == 200 and resp.text else "Unknown Vendor"
        except Exception:
            vendor = "Unknown Vendor"
        self.vendor_cache[mac] = vendor
        return vendor

    def _check_port(self, ip, port, name, timeout=0.3):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((ip, port)) == 0:
                    return name
        except Exception:
            pass
        return None

    def scan_ports(self, ip):
        detected = []
        futures = []
        for port, name in self.ports_map.items():
            futures.append(self.executor.submit(self._check_port, ip, port, name))
        for f in as_completed(futures):
            try:
                if r := f.result(): detected.append(r)
            except Exception: pass
        return detected

    def analyze(self, ip, mac):
        vendor = self.get_vendor(mac)
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except Exception:
            hostname = "Unknown Host"
        
        services = self.scan_ports(ip)
        dev_type = "UNKNOWN NODE"
        icon = "?"

        # Logic nhận diện thông minh (Smart Detection Logic)
        try:
            if "Apple" in vendor:
                dev_type = "APPLE DEVICE"; icon = ""
            elif any("Apple" in s for s in services):
                dev_type = "APPLE SERVICE"; icon = ""
            elif any("Cam" in s for s in services) or any(v in vendor for v in ("Hikvision", "Dahua")):
                dev_type = "SURVEILLANCE CAM"; icon = "📷"
            elif any("Remote Desktop" in s or "RDP" in s for s in services) or "Windows" in vendor:
                dev_type = "WINDOWS WORKSTATION"; icon = "❖"
            elif any("Web" in s or "HTTP" in s for s in services):
                dev_type = "NET GATEWAY"; icon = "🌐"
        except Exception: pass

        return {"ip": ip, "mac": mac, "vendor": vendor, "hostname": hostname, "type": dev_type, "icon": icon}

# ----------------- MODULE: TELEGRAM BOT -----------------
class TelegramService:
    def __init__(self, token, chat_id, controller):
        self.token = token
        self.chat_id = str(chat_id)
        self.controller = controller
        self.bot = None
        self._last_alert_at = 0.0
        
        if self.token and "YOUR_" not in self.token:
            try:
                self.bot = telebot.TeleBot(token, parse_mode='HTML')
                self.setup_handlers()
                self.send_startup_msg()
            except Exception as e:
                logging.error(f"Telegram Init Failed: {e}")

    def send_startup_msg(self):
        msg = (
            f"<b>🔰 THACH SENSOR V18.5 ONLINE</b>\n"
            f"<code>MODE    : ACTIVE MONITORING</code>\n"
            f"<code>STATUS  : SCANNING...</code>"
        )
        try: self.bot.send_message(self.chat_id, msg)
        except: pass

    def setup_handlers(self):
        @self.bot.message_handler(commands=['start', 'stop', 'status'])
        def handle_msg(message):
            text = (message.text or "").lower()
            if "/start" in text:
                self.controller.is_scanning = True
                self.bot.reply_to(message, "<b>🚀 SYSTEM RESUMED</b>")
            elif "/stop" in text:
                self.controller.is_scanning = False
                self.bot.reply_to(message, "<b>🛑 SYSTEM PAUSED</b>")
            elif "/status" in text:
                count = len(self.controller.detected_macs)
                self.bot.reply_to(message, f"<b>📊 LIVE TARGETS:</b> <code>{count}</code>")

    def send_alert(self, d):
        if not self.bot: return
        now = time.time()
        if now - self._last_alert_at < CONFIG["ALERT_COOLDOWN"]: return
        self._last_alert_at = now

        msg = (
            f"<b>🚨 INTRUSION DETECTED {d['icon']}</b>\n"
            f"<pre>"
            f"📡 IP     : {d['ip']}\n"
            f"🔌 MAC    : {d['mac']}\n"
            f"🏭 VENDOR : {d['vendor'][:25]}\n"
            f"💻 HOST   : {d['hostname']}\n"
            f"🕵️ TYPE   : {d['type']}\n"
            f"⏰ TIME   : {datetime.now().strftime('%H:%M:%S')}"
            f"</pre>\n"
            f"<i>🔒 Thach Sensor Cyber Unit</i>"
        )
        try: self.bot.send_message(self.chat_id, msg)
        except Exception as e: logging.debug(f"Alert failed: {e}")

    def start(self):
        if self.bot:
            try: self.bot.infinity_polling(timeout=10, long_polling_timeout=5)
            except: pass

# ----------------- MODULE: MAIN CONTROLLER -----------------
class ThachSensorV18_Ultimate:
    def __init__(self):
        self.local_ip = NetworkManager.get_local_ip()
        self.target_net = NetworkManager.get_subnet(self.local_ip)
        
        self.fingerprinter = DeviceFingerprinter(workers=min(20, CONFIG["WORKERS"]))
        self.detected_macs = self._load_persisted() # Load history (Persistence)
        self.session_macs = set() # Current session only
        
        self.executor = ThreadPoolExecutor(max_workers=CONFIG["WORKERS"])
        self.bot = TelegramService(CONFIG["TG_TOKEN"], CONFIG["CHAT_ID"], self)
        
        self.is_scanning = True
        self._running = True

    def _load_persisted(self):
        if os.path.exists(CONFIG["PERSIST_FILE"]):
            try:
                with open(CONFIG["PERSIST_FILE"], "r") as f:
                    return set(json.load(f))
            except: pass
        return set()

    def _persist_macs(self):
        try:
            with open(CONFIG["PERSIST_FILE"], "w") as f:
                json.dump(list(self.detected_macs), f)
        except: pass

    def boot_sequence(self):
        os.system('cls' if os.name == 'nt' else 'clear')
        print(f"{Fore.LIGHTCYAN_EX}{Style.BRIGHT}")
        print(r"""
  ████████╗██╗  ██╗ █████╗  ██████╗██╗  ██╗
  ╚══██╔══╝██║  ██║██╔══██╗██╔════╝██║  ██║
     ██║   ███████║███████║██║     ███████║
     ██║   ██╔══██║██╔══██║██║     ██╔══██║
     ██║   ██║  ██║██║  ██║╚██████╗██║  ██║
     ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝ V18.5
        """)
        print(f"{Fore.MAGENTA}    [ SYSTEM ACTIVE ] {Fore.WHITE}/// {Fore.LIGHTGREEN_EX}CYBER INTELLIGENCE UNIT{Style.RESET_ALL}\n")
        time.sleep(1)

    def process_device(self, ip, mac):
        # Logic 1: Nếu chưa từng thấy trong phiên này -> In ra màn hình
        if mac not in self.session_macs:
            self.session_macs.add(mac)
            info = self.fingerprinter.analyze(ip, mac)
            
            # Tô màu Console
            c = Fore.LIGHTGREEN_EX
            if "APPLE" in info['type']: c = Fore.LIGHTMAGENTA_EX
            elif "CAM" in info['type']: c = Fore.LIGHTRED_EX
            elif "WINDOWS" in info['type']: c = Fore.LIGHTBLUE_EX
            
            print(f"{Fore.CYAN}║ {c}{info['ip']:<15} {Fore.CYAN}║ {Fore.WHITE}{info['mac']} {Fore.CYAN}║ {Fore.YELLOW}{info['vendor'][:20]:<20} {Fore.CYAN}║ {c}{info['type']}")
            
            # Logic 2: Nếu chưa từng thấy trong LỊCH SỬ -> Gửi cảnh báo Telegram
            if mac not in self.detected_macs:
                self.detected_macs.add(mac)
                self._persist_macs()
                self.bot.send_alert(info)

    def run(self):
        # Start Bot Thread
        threading.Thread(target=self.bot.start, daemon=True).start()
        
        self.boot_sequence()
        print(f"{Fore.LIGHTCYAN_EX}╔{'═'*16}╦{'═'*19}╦{'═'*22}╦{'═'*20}")
        print(f"║ IP ADDRESS      ║ MAC ADDRESS       ║ VENDOR               ║ TYPE")
        print(f"╠{'═'*16}╬{'═'*19}╬{'═'*22}╬{'═'*20}")

        try:
            while self._running:
                if self.is_scanning:
                    packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=self.target_net)
                    try:
                        # Scapy scanning
                        ans = scapy.srp(packet, timeout=2, verbose=0, iface=CONFIG.get("INTERFACE_NAME"))[0]
                        for _, r in ans:
                            # Đẩy vào luồng xử lý riêng để không bị đơ
                            self.executor.submit(self.process_device, r.psrc, r.hwsrc)
                    except PermissionError:
                        print(f"{Fore.RED}[!] ERROR: Run as Administrator/Root required!")
                        break
                    except Exception as e:
                        # logging.error(f"Scan error: {e}")
                        pass
                time.sleep(CONFIG["SCAN_INTERVAL"])
        except KeyboardInterrupt:
            print(f"\n{Fore.RED}[!] SESSION TERMINATED.{Style.RESET_ALL}")
            self._persist_macs()

if __name__ == "__main__":
    ThachSensorV18_Ultimate().run()