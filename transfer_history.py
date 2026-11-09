import json
import os
from datetime import datetime
import threading

_lock = threading.RLock()


def _locked(func):

    def wrapper(*args, **kwargs):

        with _lock:

            return func(*args, **kwargs)

    wrapper.__name__ = func.__name__
    wrapper.__doc__ = func.__doc__

    return wrapper


HISTORY_FILE = "transfer_history.json"


@_locked
def save_transfer(
    username,
    ip,
    action,
    filename,
    size,
    file_type,
    recipient="-"
):

    history = []

    if os.path.exists(HISTORY_FILE):

        try:
            with open(HISTORY_FILE, "r") as file:
                history = json.load(file)
        except Exception:
            history = []

    now = datetime.now()

    history.append({
        "username": username,
        "ip": ip,
        "action": action,
        "filename": filename,
        "size": size,
        "type": file_type,
        "recipient": recipient,
        "date": now.strftime("%Y-%m-%d"),
        "time": now.strftime("%H:%M:%S")
    })

    with open(HISTORY_FILE, "w") as file:
        json.dump(history, file, indent=4)


@_locked
def get_transfer_history():

    if not os.path.exists(HISTORY_FILE):
        return "No transfer history."

    try:

        with open(HISTORY_FILE, "r") as file:
            history = json.load(file)

    except Exception:
        return "No transfer history."

    if not history:
        return "No transfer history."

    result = ""

    for item in history:

        result += (
            f"User: {item['username']} | "
            f"Action: {item['action']} | "
            f"File: {item['filename']} | "
            f"Size: {item['size']} bytes | "
            f"Type: {item['type']} | "
            f"To: {item['recipient']} | "
            f"Date: {item['date']} | "
            f"Time: {item['time']}\n"
        )

    return result