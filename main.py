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

#------------------- Configuration -----------------

CONFIG = {
    "TG_TOKEN": os.environ.get("TG_TOKEN", "YOUR_BOT_TOKEN_HERE"), 
    "CHAT_ID": os.environ.get("CHAT_ID", "YOUR_CHAT_ID_HERE"),
    
    "VENDOR_API": "https://api.macvendors.co/",
    "SCAN_INTERVAL": 2,
    "WORKERS": 50,
    
    # Network card name (Users should fill in the name according to their computer)
    "INTERFACE_NAME": "Intel(R) Wi-Fi 6E AX211 160MHz", 
    
    "PERSIST_FILE": "detected_macs.json",
    "ALERT_COOLDOWN": 1.5,
}

# init
init(autoreset=True)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

try:
    import telebot
    import scapy.all as scapy
    scapy.conf.iface = CONFIG["INTERFACE_NAME"]
except ImportError:
    sys.exit(f"{Fore.RED}❌ Missing libs. Install: pip install pytelegrambotapi scapy colorama requests{Style.RESET_ALL}")
except Exception as e:
    logging.warning("Scapy iface setup warning: %s", e)

# ----------------- NetworkManager -----------------
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

# ----------------- DeviceFingerprinter -----------------
class DeviceFingerprinter:
    def __init__(self, workers=10):
        self.vendor_cache = {}
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
        if not mac:
            return "Unknown Vendor"
        if mac in self.vendor_cache:
            return self.vendor_cache[mac]
        try:
            resp = requests.get(CONFIG["VENDOR_API"] + mac, timeout=1.5)
            vendor = resp.text.strip() if resp.status_code == 200 and resp.text else "Unknown Vendor"
        except Exception:
            vendor = "Unknown Vendor"
        self.vendor_cache[mac] = vendor
        return vendor

    def _check_port(self, ip, port, name, timeout=0.2):
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
                r = f.result()
                if r:
                    detected.append(r)
            except Exception:
                pass
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

        try:
            if "Apple" in vendor:
                dev_type = "APPLE DEVICE"
                icon = ""
            elif any("Apple" in s for s in services):
                dev_type = "APPLE SERVICE"
                icon = ""
            elif any("Cam" in s for s in services) or any(v in vendor for v in ("Hikvision", "Dahua")):
                dev_type = "SURVEILLANCE CAM"
                icon = "📷"
            elif any("Remote Desktop" in s or "RDP" in s for s in services) or "Windows" in vendor:
                dev_type = "WINDOWS WORKSTATION"
                icon = "❖"
            elif any("Web" in s or "HTTP" in s for s in services):
                dev_type = "NET GATEWAY"
                icon = "🌐"
        except Exception:
            pass

        return {"ip": ip, "mac": mac, "vendor": vendor, "hostname": hostname, "type": dev_type, "icon": icon}

# ----------------- TelegramService -----------------
class TelegramService:
    def __init__(self, token, chat_id, controller):
        self.bot = telebot.TeleBot(token, parse_mode='HTML')
        self.chat_id = str(chat_id)
        self.controller = controller
        self._last_alert_at = 0.0
        self._running = True
        self.setup_handlers()
        # startup message (use self.chat_id)
        try:
            startup_msg = (
                f"<b>🔰 THACH SENSOR V18.3 ONLINE</b>\n"
                f"<code>MODE    : AUTO-PILOT (INSTANT)</code>\n"
                f"<code>STATUS  : SCANNING...</code>"
            )
            self.bot.send_message(self.chat_id, startup_msg)
        except Exception as e:
            logging.debug("Telegram startup message failed: %s", e)

    def setup_handlers(self):
        @self.bot.message_handler(commands=['start', 'stop', 'status'])
        def handle_msg(message):
            text = (message.text or "").lower()
            try:
                if "/start" in text:
                    self.controller.start_scan()
                    self.bot.reply_to(message, "<b>🚀 SYSTEM RESUMED</b>")
                elif "/stop" in text:
                    self.controller.stop_scan()
                    self.bot.reply_to(message, "<b>🛑 SYSTEM PAUSED</b>")
                elif "/status" in text:
                    count = len(self.controller.detected_macs)
                    self.bot.reply_to(message, f"<b>📊 LIVE TARGETS:</b> <code>{count}</code>")
            except Exception as e:
                logging.debug("Handler error: %s", e)

    def send_alert(self, d):
        now = time.time()
        if now - self._last_alert_at < CONFIG["ALERT_COOLDOWN"]:
            return
        self._last_alert_at = now

        timestamp = datetime.now().strftime("%H:%M:%S")
        msg = (
            f"<b>🚨 NEW TARGET DETECTED {d['icon']}</b>\n"
            f"<pre>"
            f"📡 IP    : {d['ip']}\n"
            f"🔌 MAC   : {d['mac']}\n"
            f"🏭 VENDOR: {d['vendor'][:30]}\n"
            f"💻 HOST  : {d['hostname']}\n"
            f"🕵️ TYPE  : {d['type']}\n"
            f"⏰ TIME  : {timestamp}"
            f"</pre>\n"
            f"<i>🔒 Thach Sensor Cyber Unit</i>"
        )
        try:
            self.bot.send_message(self.chat_id, msg)
        except Exception as e:
            logging.debug("Failed to send alert: %s", e)

    def start(self):
        # run polling until stopped
        while self._running:
            try:
                self.bot.infinity_polling(timeout=10, long_polling_timeout=5)
            except Exception as e:
                logging.debug("Telegram polling error: %s", e)
                time.sleep(2)

    def stop(self):
        self._running = False
        try:
            self.bot.stop_polling()
        except Exception:
            pass

# ----------------- Controller -----------------
class ThachSensorV18_Ultimate:
    def __init__(self):
        self.local_ip = NetworkManager.get_local_ip()
        self.target_net = NetworkManager.get_subnet(self.local_ip)
        self.iface = CONFIG["INTERFACE_NAME"]

        self.fingerprinter = DeviceFingerprinter(workers=min(20, CONFIG["WORKERS"]))
        self.detected_macs = set(self._load_persisted())
        self.executor = ThreadPoolExecutor(max_workers=CONFIG["WORKERS"])

        self.bot = TelegramService(CONFIG["TG_TOKEN"], CONFIG["CHAT_ID"], self)

        self.is_scanning = True
        self._running = True
        self._scan_lock = threading.Lock()

        # UI state for periodic header redraw
        self.scan_count = 0
        self._header_interval = 5  # redraw header every N scans

    def _load_persisted(self):
        try:
            if os.path.exists(CONFIG["PERSIST_FILE"]):
                with open(CONFIG["PERSIST_FILE"], "r") as f:
                    data = json.load(f)
                    return data if isinstance(data, list) else []
        except Exception:
            pass
        return []

    def _persist_macs(self):
        try:
            with open(CONFIG["PERSIST_FILE"], "w") as f:
                json.dump(list(self.detected_macs), f)
        except Exception:
            pass

    def boot_sequence(self):
        banner = r"""
  ████████╗██╗  ██╗ █████╗  ██████╗██╗  ██╗
  ╚══██╔══╝██║  ██║██╔══██╗██╔════╝██║  ██║
     ██║   ███████║███████║██║     ███████║
     ██║   ██╔══██║██╔══██║██║     ██╔══██║
     ██║   ██║  ██║██║  ██║╚██████╗██║  ██║
     ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
        """
        print(f"{Fore.LIGHTCYAN_EX}{Style.BRIGHT}{banner}")
        print(f"{Fore.MAGENTA}    [ SYSTEM V18.3 ] {Fore.WHITE}/// {Fore.LIGHTGREEN_EX}CYBER INTELLIGENCE UNIT {Fore.WHITE}/// {Fore.MAGENTA}[ AUTO-PILOT ]    {Style.RESET_ALL}\n")
        logs = [
            f"[0x0010] ⚙️ Initializing Kernel Core...",
            f"[0x002F] 📡 Mounting Interface: {self.iface}",
            f"[0x004A] 🔓 Decrypting Vendor DB...",
            f"[0x008C] 🎯 Targeting Subnet: {self.target_net}",
            f"[0x00FF] 🔗 Uplink to Telegram...",
            f"[0x1000] 🚀 ENGAGING ARP RECONNAISSANCE..."
        ]
        for log in logs:
            print(f"{Fore.BLUE}{log.split(']')[0]}] {Fore.LIGHTGREEN_EX}{log.split('] ')[1]}")
            time.sleep(0.05)
        time.sleep(0.2)
        print(f"\n{Back.LIGHTGREEN_EX}{Fore.BLACK}  >> SYSTEM FULLY OPERATIONAL - SCANNING NOW <<  {Style.RESET_ALL}\n")

    def start_scan(self):
        with self._scan_lock:
            self.is_scanning = True
        print(f"\n{Fore.GREEN}[!] SYSTEM RESUMED{Style.RESET_ALL}")

    def stop_scan(self):
        with self._scan_lock:
            self.is_scanning = False
        print(f"\n{Fore.YELLOW}[!] SYSTEM PAUSED{Style.RESET_ALL}")

    def print_table_header(self):
        print(f"{Fore.LIGHTCYAN_EX}╔{'═'*17}╦{'═'*19}╦{'═'*25}╦{'═'*22}╗")
        print(f"║ {Fore.WHITE}IP ADDRESS      {Fore.LIGHTCYAN_EX}║ {Fore.WHITE}MAC ADDRESS       {Fore.LIGHTCYAN_EX}║ {Fore.WHITE}VENDOR                  {Fore.LIGHTCYAN_EX}║ {Fore.WHITE}DEVICE TYPE          {Fore.LIGHTCYAN_EX}║")
        print(f"╠{'═'*17}╬{'═'*19}╬{'═'*25}╬{'═'*22}╣{Style.RESET_ALL}")

    def print_status_banner(self):
        # Small decorative header shown periodically during scanning
        title = " THACH SENSOR  v18.3 "
        left = f"{Fore.WHITE}{Back.MAGENTA} {title} {Style.RESET_ALL}"
        stats = f"{Fore.YELLOW}Targets:{len(self.detected_macs)}{Style.RESET_ALL}"
        now = datetime.now().strftime("%H:%M:%S")
        stamp = f"{Fore.CYAN}{now}{Style.RESET_ALL}"
        print(f"\n{left}  {stats}  {stamp}\n")

    def print_table_footer(self):
        print(f"{Fore.LIGHTCYAN_EX}╚{'═'*17}╩{'═'*19}╩{'═'*25}╩{'═'*22}╝{Style.RESET_ALL}\n")
        print(f"{Fore.GREEN}Active targets: {len(self.detected_macs)}{Style.RESET_ALL}\n")

    def process_device(self, ip, mac):
        try:
            info = self.fingerprinter.analyze(ip, mac)
            c = Fore.LIGHTGREEN_EX
            if "APPLE" in info['type']:
                c = Fore.LIGHTMAGENTA_EX
            elif "CAM" in info['type']:
                c = Fore.LIGHTRED_EX
            elif "WINDOWS" in info['type']:
                c = Fore.LIGHTBLUE_EX
            elif "UNKNOWN" in info['type']:
                c = Fore.LIGHTBLACK_EX

            vendor_short = (info['vendor'][:23] + '..') if len(info['vendor']) > 23 else info['vendor']
            row = (
                f"{Fore.LIGHTCYAN_EX}║ {c}{info['ip']:<15} "
                f"{Fore.LIGHTCYAN_EX}║ {Fore.WHITE}{info['mac']} "
                f"{Fore.LIGHTCYAN_EX}║ {Fore.YELLOW}{vendor_short:<23} "
                f"{Fore.LIGHTCYAN_EX}║ {c}{info['icon']} {info['type']:<18} {Fore.LIGHTCYAN_EX}║{Style.RESET_ALL}"
            )
            print(row)
            # send alert async to avoid blocking
            try:
                self.bot.send_alert(info)
            except Exception as e:
                logging.debug("Bot send_alert error: %s", e)
        except Exception:
            logging.exception("process_device failed for %s %s", ip, mac)

    def scan_loop(self):
        while self._running:
            if self.is_scanning:
                try:
                    packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=self.target_net)
                    ans = scapy.srp(packet, timeout=2, verbose=0, iface=self.iface)[0]
                    for _, r in ans:
                        mac = r.hwsrc
                        ip = r.psrc
                        if mac and mac not in self.detected_macs:
                            self.detected_macs.add(mac)
                            # persist incrementally
                            self._persist_macs()
                            self.executor.submit(self.process_device, ip, mac)
                    # update counter and occasionally redraw header/banner
                    self.scan_count += 1
                    if self.scan_count % self._header_interval == 0:
                        self.print_status_banner()
                except PermissionError:
                    logging.error("Permission denied: scapy requires elevated privileges.")
                    self._running = False
                    break
                except Exception:
                    logging.exception("scan_loop error")
                time.sleep(CONFIG["SCAN_INTERVAL"])
            else:
                time.sleep(1)

    def run(self):
        # start telegram bot thread
        t = threading.Thread(target=self.bot.start, daemon=True)
        t.start()
        # boot visuals
        self.boot_sequence()
        self.print_table_header()
        try:
            self.scan_loop()
        finally:
            self.shutdown()

    def shutdown(self):
        logging.info("Shutting down sensor...")
        self._running = False
        try:
            self.bot.stop()
        except Exception:
            pass
        try:
            self.executor.shutdown(wait=False)
        except Exception:
            pass
        try:
            self.fingerprinter.executor.shutdown(wait=False)
        except Exception:
            pass
        # print footer / final UI summary before persisting
        try:
            self.print_table_footer()
        except Exception:
            pass
        self._persist_macs()
        logging.info("Shutdown complete.")

if __name__ == "__main__":
    try:
        ThachSensorV18_Ultimate().run()
    except KeyboardInterrupt:
        print(f"\n{Fore.LIGHTCYAN_EX}╚{'═'*87}╝")
        print(f"{Fore.RED}[!] SESSION TERMINATED.{Style.RESET_ALL}")