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


HISTORY_FILE = "login_history.json"


@_locked
def save_login(username, ip, status):

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
        "date": now.strftime("%Y-%m-%d"),
        "time": now.strftime("%H:%M:%S"),
        "status": status
    })

    with open(HISTORY_FILE, "w") as file:
        json.dump(history, file, indent=4)


@_locked
def get_history():

    if not os.path.exists(HISTORY_FILE):
        return "No login history."

    try:

        with open(HISTORY_FILE, "r") as file:
            history = json.load(file)

    except Exception:
        return "No login history."

    if not history:
        return "No login history."

    result = ""

    for item in history:

        result += (
            f"User: {item['username']} | "
            f"IP: {item['ip']} | "
            f"Date: {item['date']} | "
            f"Time: {item['time']} | "
            f"Status: {item['status']}\n"
        )

    return result