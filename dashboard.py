import streamlit as st
import os
import time

LOG_FILE = "logs/alerts.log"

st.set_page_config(page_title="Mini-Snort IDS", layout="wide")
st.title("🛡️ Mini-Snort IDS Dashboard")
st.markdown("### Real-time Intrusion Alerts")

# Auto refresh every 3 seconds (Streamlit-safe)
st.autorefresh(interval=3000, key="refresh")

def read_logs():
    if not os.path.exists(LOG_FILE):
        return "No alerts yet."
    with open(LOG_FILE, "r") as f:
        return f.read()

logs = read_logs()

st.text_area(
    label="Alerts",
    value=logs,
    height=400,
    key="alerts_box"   # 👈 UNIQUE KEY (important)
)
