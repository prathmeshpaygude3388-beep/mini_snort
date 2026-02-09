# Mini-Snort IDS 🛡️

Mini-Snort IDS is a lightweight, Snort-inspired Intrusion Detection System (IDS) built using Python and Scapy.  
It monitors live network traffic, detects suspicious activities using rule-based detection, and displays alerts through a Streamlit web dashboard.

---

## 🔍 Features

- Live packet capture using Scapy  
- Signature-based and heuristic-based detection  
- Detects:
  - TCP SYN scans
  - Suspicious UDP activity
  - HTTP and HTTPS traffic
  - Plaintext password leakage
  - SQL injection patterns
  - Abnormally large packets
- Real-time alert logging
- Web-based monitoring dashboard using Streamlit

---

## 🧠 Detection Approach

The system uses:
- **Signature-based detection** (known attack patterns)
- **Heuristic-based detection** (thresholds and indicators)

Detection is based on:
- TCP flags
- Port numbers
- Packet size
- Payload keyword and pattern matching

---

## 🧩 Project Architecture