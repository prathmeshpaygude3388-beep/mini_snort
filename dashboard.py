import streamlit as st
import time
import os

LOG_FILE = "logs/alerts.log"

st.set_page_config(page_title="Mini-Snort IDS", layout="wide")
st.title("🛡️ Mini-Snort IDS Dashboard")

st.markdown("### Real-time Intrusion Alerts")

placeholder = st.empty()

def read_logs():
    if not os.path.exists(LOG_FILE):
        return []
    with open(LOG_FILE, "r") as f:
        return f.readlines()

while True:
    logs = read_logs()
    placeholder.text_area(
        "Alerts",
        "".join(logs),
        height=400
    )
    time.sleep(3)
