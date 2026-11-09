from cryptography.fernet import Fernet
import os
import threading

KEY_FILE = "encryption.key"

_lock = threading.Lock()


def create_key():

    with _lock:

        if not os.path.exists(KEY_FILE):

            key = Fernet.generate_key()

            with open(KEY_FILE, "wb") as file:
                file.write(key)


def get_key():

    create_key()

    with _lock:

        with open(KEY_FILE, "rb") as file:
            return file.read()


def encrypt_data(data):

    key = get_key()

    cipher = Fernet(key)

    return cipher.encrypt(data)


def decrypt_data(data):

    key = get_key()

    cipher = Fernet(key)

    return cipher.decrypt(data)