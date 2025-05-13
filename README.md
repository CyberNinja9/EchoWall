# EchoWall
 Python-based honeypot designed to detect ICMP echo requests (pings), log them, send custom warning replies, and alert the user in real-time via Telegram. It simulates a defensive system that's aware of reconnaissance and takes action instantly.

---

##  Features

- Detects ICMP echo requests (e.g., Nmap, CMD ping)
- Sends custom ICMP replies to confuse or warn the attacker
- Logs attacker IPs with timestamps
- Sends real-time alerts via **Telegram Bot**
- Simulates a fake SSH server and logs connections
- Blocks malicious IPs using `iptables`
- Stores all events in a local log file

---

##  Technologies Used

- **Python 3**
- **Scapy** – for packet sniffing and crafting
- **Colorama** – for CLI output
- **Iptables** – for real-time IP blocking
- **Telegram Bot API** – for notifications




