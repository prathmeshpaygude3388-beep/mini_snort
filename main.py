"""
Mini-Snort IDS
Main Controller File

Author: You
Description:
- Starts packet sniffing
- Loads detection rules
- Processes packets
- Generates alerts
"""

from detector.packet_sniffer import start_sniffing
from detector.rule_engine import load_rules, check_rules
from detector.alert import log_alert

# ---------------- ALERT DEDUPLICATION ----------------
# Prevents repeated alert spam
recent_alerts = set()


def banner():
    print("=" * 50)
    print("        🛡️  MINI-SNORT IDS STARTED  🛡️")
    print("   Lightweight Intrusion Detection System")
    print("=" * 50)


# Load rules once at startup
rules = load_rules()


def process_packet(packet):
    """
    Callback function for every captured packet
    """
    try:
        alerts = check_rules(packet, rules)

        for alert in alerts:
            # Log alert only once
            if alert not in recent_alerts:
                log_alert(alert)
                recent_alerts.add(alert)

    except Exception as e:
        print("Error processing packet:", e)


if __name__ == "__main__":
    banner()
    print("[*] Loading rules...")
    print(f"[*] {len(rules)} rules loaded successfully")
    print("[*] Starting live packet capture...\n")

    # Start sniffing packets
    start_sniffing(process_packet)
