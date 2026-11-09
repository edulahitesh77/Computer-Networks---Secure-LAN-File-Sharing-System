import json
import hashlib
import os
import threading

_lock = threading.RLock()


def _locked(func):

    def wrapper(*args, **kwargs):

        with _lock:

            return func(*args, **kwargs)

    wrapper.__name__ = func.__name__
    wrapper.__doc__ = func.__doc__

    return wrapper


USERS_FILE = "users.json"


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


@_locked
def load_users():
    if not os.path.exists(USERS_FILE):
        return {}

    try:
        with open(USERS_FILE, "r") as file:
            return json.load(file)
    except Exception:
        return {}


@_locked
def save_users(users):
    with open(USERS_FILE, "w") as file:
        json.dump(users, file, indent=4)


@_locked
def create_default_users():

    users = load_users()

    default_users = {
        "admin": {
            "password": hash_password("admin123"),
            "role": "admin"
        },
        "hitesh": {
            "password": hash_password("1234"),
            "role": "user"
        },
        "rahul": {
            "password": hash_password("1234"),
            "role": "user"
        }
    }

    changed = False

    for username, data in default_users.items():

        if username not in users:
            users[username] = data
            changed = True

    if changed:
        save_users(users)


@_locked
def verify_user(username, password):

    users = load_users()

    if username not in users:
        return False

    password_hash = hash_password(password)

    return users[username]["password"] == password_hash


@_locked
def get_role(username):

    users = load_users()

    if username in users:
        return users[username]["role"]

    return None


@_locked
def register_user(username, password):

    users = load_users()

    if username in users:
        return False

    users[username] = {
        "password": hash_password(password),
        "role": "user"
    }

    save_users(users)

    return True


@_locked
def delete_user(username):

    users = load_users()

    if username not in users:
        return False

    if username == "admin":
        return False

    del users[username]

    save_users(users)

    return True


@_locked
def get_users():

    users = load_users()

    result = []

    for username, data in users.items():

        result.append(
            f"{username} | Role: {data['role']}"
        )

    return result