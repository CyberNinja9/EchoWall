import socket
import time
from datetime import datetime
from colorama import Fore, Style
import subprocess
import requests

# === Configuration ===
HOST = '0.0.0.0'
PORT = 22
BANNER = "SSH-2.0 Hi Hacker. Your IP is already logged. Proceed at your own risk."
BOT_TOKEN = '8185602548:AAH__ML5sX4yqBtKjOH9cePl4a2T4iuUF5A'
CHAT_ID = '6945286234'

# === Get GeoIP info ===
def get_geoip(ip):
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}", timeout=5).json()
        if res.get("status") == "success":
            return f"{res['country']}, {res['regionName']} ({res['isp']})"
    except:
        pass
    return "Unknown"

# === Send Telegram Alert ===
def send_telegram_alert(ip, geo):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    message = (
        f"*[SSH Trap Triggered]*\n"
        f"`Time:` {timestamp}\n"
        f"`IP:` [{ip}](http://{ip})\n"
        f"`Geo:` {geo}\n"
        f"`Banner:` {BANNER}"
    )
    try:
        url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
        payload = {
            'chat_id': CHAT_ID,
            'text': message,
            'parse_mode': 'Markdown'
        }
        requests.post(url, data=payload, timeout=5)
    except Exception as e:
        print(Fore.YELLOW + f"[!] Telegram alert failed: {e}" + Style.RESET_ALL)

# === Log Locally ===
def log_connection(ip, port, geo):
    with open("honey_tcp_log.txt", "a") as log:
        log.write(f"{datetime.now()} | IP: {ip}:{port} | Geo: {geo}\n")

# === Block IP ===
def block_ip(ip):
    print(Fore.MAGENTA + f"[🛡] Blocking IP {ip} using iptables..." + Style.RESET_ALL)
    subprocess.call(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])

# === Start Trap ===
def start_fake_ssh():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((HOST, PORT))
            server.listen()

            print(Fore.CYAN + f"[🔌] Fake SSH trap listening on port {PORT}..." + Style.RESET_ALL)

            while True:
                conn, addr = server.accept()
                ip, port = addr
                print(Fore.RED + f"[⚠️] Connection from {ip}:{port}" + Style.RESET_ALL)

                geo = get_geoip(ip)
                log_connection(ip, port, geo)
                send_telegram_alert(ip, geo)

                try:
                    conn.sendall(BANNER.encode("utf-8"))
                    time.sleep(1)
                except Exception as e:
                    print(Fore.YELLOW + f"[!] Failed to send banner: {e}" + Style.RESET_ALL)

                conn.close()
                block_ip(ip)

    except KeyboardInterrupt:
        print(Fore.GREEN + "\n[✔] Fake SSH trap stopped by user." + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"[❌] Error: {e}" + Style.RESET_ALL)

# Run it
start_fake_ssh()
