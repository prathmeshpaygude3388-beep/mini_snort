from scapy.layers.inet import TCP, UDP, ICMP
import re

# ---------------- GLOBAL COUNTERS ----------------
# Persistent across packets
udp_counter = {}

def load_rules():
    """
    Loads rules from rules/rules.txt
    """
    rules = []
    with open("rules/rules.txt", "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                rules.append(line)
    return rules


def check_rules(packet, rules):
    """
    Applies detection rules on each packet
    """
    alerts = []

    # ---------- TCP BASED RULES ----------
    if packet.haslayer(TCP):
        tcp = packet[TCP]

        if "TCP_SYN_SCAN" in rules and tcp.flags == "S":
            alerts.append("TCP SYN Scan detected")

        if "TCP_FIN_SCAN" in rules and tcp.flags == "F":
            alerts.append("TCP FIN Scan detected")

        if "TCP_NULL_SCAN" in rules and tcp.flags == 0:
            alerts.append("TCP NULL Scan detected")

        if "TCP_XMAS_SCAN" in rules and tcp.flags == 0x29:
            alerts.append("TCP XMAS Scan detected")

        if "HTTP_PORT_ACCESS" in rules and tcp.dport == 80:
            alerts.append("HTTP traffic detected on port 80")

        if "HTTPS_PORT_ACCESS" in rules and tcp.dport == 443:
            alerts.append("HTTPS traffic detected on port 443")

        if "TELNET_ACCESS" in rules and tcp.dport == 23:
            alerts.append("Insecure Telnet access detected")

        if "FTP_ACCESS" in rules and tcp.dport == 21:
            alerts.append("FTP access detected")

    # ---------- UDP RULES (THRESHOLD-BASED) ----------
    if packet.haslayer(UDP) and "UDP_SCAN" in rules:
        udp = packet[UDP]
        src_port = udp.sport

        udp_counter[src_port] = udp_counter.get(src_port, 0) + 1

        # Alert only once when threshold is reached
        if udp_counter[src_port] == 25:
            alerts.append("Possible UDP scan detected")

    # ---------- ICMP RULES ----------
    if packet.haslayer(ICMP):
        if "ICMP_ECHO_REQUEST" in rules:
            alerts.append("ICMP packet detected (Ping/Flood)")

    # ---------- PAYLOAD INSPECTION ----------
    if packet.haslayer(TCP) and bytes(packet[TCP].payload):
        payload = bytes(packet[TCP].payload).lower()

        if "PLAINTEXT_PASSWORD" in rules and b"password" in payload:
            alerts.append("Plaintext password detected")

        if "PLAINTEXT_USERNAME" in rules and b"username" in payload:
            alerts.append("Plaintext username detected")

        if "SQL_INJECTION_KEYWORDS" in rules:
            if re.search(b"(select|union|drop|insert|or 1=1)", payload):
                alerts.append("Possible SQL Injection detected")

        if "XSS_KEYWORDS" in rules and b"<script>" in payload:
            alerts.append("Possible XSS attack detected")

        if "REVERSE_SHELL_KEYWORDS" in rules:
            if b"nc " in payload or b"/dev/tcp" in payload:
                alerts.append("Reverse shell pattern detected")

    # ---------- PACKET SIZE ----------
    if "LARGE_PACKET_SIZE" in rules and len(packet) > 4000:
        alerts.append("Abnormally large packet detected")

    return alerts
