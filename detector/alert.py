from datetime import datetime
import os


LOG_FILE = "logs/alerts.log"


def log_alert(message):
    """
    Logs alerts to file and prints on console
    """
    os.makedirs("logs", exist_ok=True)

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    log_entry = f"[{timestamp}] ALERT: {message}"

    with open(LOG_FILE, "a") as f:
        f.write(log_entry + "\n")

    print("🚨", log_entry)
