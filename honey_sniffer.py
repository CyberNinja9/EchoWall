from scapy.all import sniff, IP, ICMP, send
from datetime import datetime
import time
import subprocess
import requests
import socket
from colorama import Fore, Style

# === Configuration ===
PING_RATE_THRESHOLD = 3
TIME_WINDOW = 5
BOT_TOKEN = 'yourbottoken'
CHAT_ID = 'yourchatid'

# === Get Local IP (not 127.0.0.1) ===
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except:
        return "127.0.0.1"
    finally:
        s.close()

local_ip = get_local_ip()

reply_msg = "Hi Hacker. Your IP is already logged. Proceed at your own risk."
ping_log = {}
blocked_ips = set()

# === Telegram Alert ===
def send_telegram_alert(message, parse_mode=None):
    url = f'https://api.telegram.org/bot{BOT_TOKEN}/sendMessage'
    payload = {
        'chat_id': CHAT_ID,
        'text': message
    }
    if parse_mode:
        payload['parse_mode'] = parse_mode
    try:
        requests.post(url, data=payload, timeout=5)
    except Exception as e:
        print(f"[ERROR] Telegram alert failed: {e}")

# === GeoIP Lookup ===
def get_geoip_info(ip):
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        if res.status_code == 200:
            data = res.json()
            if data.get("status") == "success":
                country = data.get("country", "Unknown")
                region = data.get("regionName", "")
                isp = data.get("isp", "")
                return f"{country}, {region} ({isp})"
    except:
        pass
    return "Unknown"

# === Block IP with iptables ===
def block_ip(ip):
    if ip not in blocked_ips:
        print(Fore.MAGENTA + f"[BLOCK] Blocking IP {ip} using iptables..." + Style.RESET_ALL)
        subprocess.call(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
        blocked_ips.add(ip)
    else:
        print(Fore.MAGENTA + f"[INFO] IP {ip} is already blocked." + Style.RESET_ALL)

# === Send ICMP Reply + Alert + Log ===
def send_custom_reply(pkt, ping_count):
    dst_ip = pkt[IP].src
    ttl = pkt[IP].ttl

    icmp_reply = IP(dst=dst_ip, src=local_ip) / \
                 ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq) / \
                 reply_msg.encode("utf-8")

    send(icmp_reply, verbose=0)
    print(Fore.YELLOW + f"[REPLY] Sent to {dst_ip} | Message: {reply_msg}" + Style.RESET_ALL)

    # Log locally
    log_entry = f"{datetime.now()} | IP: {dst_ip} | TTL: {ttl} | Pings: {ping_count} | Msg: {reply_msg}\n"
    with open("echowall_icmp_log.txt", "a") as log_file:
        log_file.write(log_entry)

    # Telegram alert
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    geo_info = get_geoip_info(dst_ip)

    alert = (
        f"*EchoWall ALERT*\n"
        f"Time: `{timestamp}`\n"
        f"Blocked IP: [{dst_ip}](http://{dst_ip})\n"
        f"Location: `{geo_info}`\n"
        f"Ping Count: `{ping_count}`\n"
        f"Message Sent: `{reply_msg}`"
    )

    send_telegram_alert(alert, parse_mode='Markdown')
    block_ip(dst_ip)

# === Handle Packet ===
def handle_packet(pkt):
    if ICMP in pkt and pkt[ICMP].type == 8:
        src_ip = pkt[IP].src
        now = time.time()

        if src_ip not in ping_log:
            ping_log[src_ip] = []

        ping_log[src_ip].append(now)
        ping_log[src_ip] = [t for t in ping_log[src_ip] if now - t < TIME_WINDOW]
        ping_count = len(ping_log[src_ip])

        print(f"[PING] From: {src_ip} | Count in {TIME_WINDOW}s: {ping_count}")

        if ping_count >= PING_RATE_THRESHOLD and src_ip not in blocked_ips:
            print(Fore.RED + f"[ALERT] Suspicious pinger detected: {src_ip}" + Style.RESET_ALL)
            send_custom_reply(pkt, ping_count)

# === Start EchoWall ===
print(Fore.CYAN + f"[EchoWall] Listening on local IP: {local_ip} for ICMP echo requests..." + Style.RESET_ALL)
sniff(filter="icmp", prn=handle_packet, store=0)
