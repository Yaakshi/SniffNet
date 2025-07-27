import time
import os
from queue import Queue

alert_queue = Queue()

# ANSI Color Codes
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"


def trigger_alert(message):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    full_msg = f"[{timestamp}] ALERT: {message}"

    # Select color based on content
    message_lower = message.lower()
    if "syn flood" in message_lower or "arp spoof" in message_lower or "null" in message_lower:
        color = RED
    elif "port scan" in message_lower or "xmas" in message_lower or "dns" in message_lower:
        color = YELLOW
    else:
        color = CYAN

    alert_queue.put(full_msg)  # Push to GUI queue

    # Print to terminal with color
    print(f"{color}{full_msg}{RESET}")
