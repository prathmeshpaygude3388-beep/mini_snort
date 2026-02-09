import streamlit as st
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "logs", "alerts.log")

st.set_page_config(page_title="Mini-Snort IDS", layout="wide")
st.title("🛡️ Mini-Snort IDS Dashboard")
st.markdown("### Real-time Intrusion Alerts")

if st.button("🔄 Refresh Alerts"):
    pass

def read_logs():
    if not os.path.exists(LOG_FILE):
        return "No alerts yet."
    with open(LOG_FILE, "r") as f:
        return f.read()

st.text_area(
    "Alerts",
    read_logs(),
    height=400,
    key="alerts_box"
)
