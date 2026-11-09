import os
import hashlib
import secrets
from datetime import datetime, timedelta

MAX_FILE_SIZE = 50 * 1024 * 1024

MAX_LOGIN_ATTEMPTS = 5

LOCK_DURATION = timedelta(minutes=5)

ALLOWED_EXTENSIONS = {
    ".txt",
    ".pdf",
    ".doc",
    ".docx",
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".py",
    ".java",
    ".c",
    ".cpp",
    ".html",
    ".css",
    ".js",
    ".zip"
}


failed_attempts = {}

sessions = {}


def generate_session_token():

    return secrets.token_hex(32)


def create_session(username):

    token = generate_session_token()

    sessions[token] = {
        "username": username,
        "created": datetime.now()
    }

    return token


def validate_session(token):

    if token not in sessions:
        return False

    session = sessions[token]

    if datetime.now() - session["created"] > timedelta(hours=2):

        del sessions[token]

        return False

    return True


def get_session_user(token):

    if validate_session(token):
        return sessions[token]["username"]

    return None


def remove_session(token):

    if token in sessions:
        del sessions[token]


def login_allowed(username):

    if username not in failed_attempts:
        return True

    attempts, locked_until = failed_attempts[username]

    # Not locked: the counter only matters once it reaches the limit.
    if attempts < MAX_LOGIN_ATTEMPTS:
        return True

    # Locked: allow again only after the lock period has passed.
    if datetime.now() >= locked_until:
        reset_login_attempts(username)

        return True

    return False


def record_failed_login(username):

    attempts = 0

    if username in failed_attempts:
        attempts = failed_attempts[username][0]

    attempts += 1

    locked_until = datetime.now()

    if attempts >= MAX_LOGIN_ATTEMPTS:
        locked_until = datetime.now() + LOCK_DURATION

    failed_attempts[username] = (attempts, locked_until)


def reset_login_attempts(username):

    if username in failed_attempts:
        del failed_attempts[username]


def validate_filename(filename):

    filename = os.path.basename(filename)

    if filename != filename.strip():
        return False

    if filename in ("", ".", ".."):
        return False

    return True


def validate_file(filename, size):

    if not validate_filename(filename):
        return False, "Invalid filename."

    if size > MAX_FILE_SIZE:
        return False, "File is too large. Maximum size is 50 MB."

    extension = os.path.splitext(filename)[1].lower()

    if extension not in ALLOWED_EXTENSIONS:
        return False, "File type is not allowed."

    return True, "Valid"


def file_hash(data):

    return hashlib.sha256(data).hexdigest()