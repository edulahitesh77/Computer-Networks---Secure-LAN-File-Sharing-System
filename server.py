import socket
import ssl
import os
import mimetypes
import json
import threading

from authentication import (
    create_default_users,
    verify_user,
    register_user,
    delete_user,
    get_users,
    get_role
)

from encryption import (
    encrypt_data,
    decrypt_data,
    get_key
)

from security import (
    login_allowed,
    record_failed_login,
    reset_login_attempts,
    create_session,
    validate_session,
    remove_session,
    validate_file,
    file_hash
)

from login_history import (
    save_login,
    get_history
)

from transfer_history import (
    save_transfer,
    get_transfer_history
)

from file_transfer import (
    send_message,
    receive_message,
    send_bytes,
    receive_bytes
)


_lock = threading.RLock()


def _locked(func):

    def wrapper(*args, **kwargs):

        with _lock:

            return func(*args, **kwargs)

    wrapper.__name__ = func.__name__
    wrapper.__doc__ = func.__doc__

    return wrapper


HOST = "0.0.0.0"
PORT = 5000

SHARED_FOLDER = "shared"

CERT_FILE = "server.crt"
KEY_FILE = "server.key"

SECURITY_LOG = "security_log.json"


os.makedirs(SHARED_FOLDER, exist_ok=True)

create_default_users()

get_key()


@_locked
def save_security_log(
    username,
    ip,
    action,
    status
):

    logs = []

    if os.path.exists(SECURITY_LOG):

        try:

            with open(
                SECURITY_LOG,
                "r"
            ) as file:

                logs = json.load(file)

        except Exception:

            logs = []

    from datetime import datetime

    now = datetime.now()

    logs.append({
        "username": username,
        "ip": ip,
        "action": action,
        "status": status,
        "date": now.strftime("%Y-%m-%d"),
        "time": now.strftime("%H:%M:%S")
    })

    with open(
        SECURITY_LOG,
        "w"
    ) as file:

        json.dump(
            logs,
            file,
            indent=4
        )


@_locked
def get_security_log():

    if not os.path.exists(
        SECURITY_LOG
    ):

        return "No security events."

    try:

        with open(
            SECURITY_LOG,
            "r"
        ) as file:

            logs = json.load(file)

    except Exception:

        return "No security events."

    result = ""

    for item in logs:

        result += (
            f"User: {item['username']} | "
            f"IP: {item['ip']} | "
            f"Action: {item['action']} | "
            f"Status: {item['status']} | "
            f"Date: {item['date']} | "
            f"Time: {item['time']}\n"
        )

    return result


def user_file_path(username, filename):

    folder = os.path.join(
        SHARED_FOLDER,
        username
    )

    os.makedirs(
        folder,
        exist_ok=True
    )

    return os.path.join(
        folder,
        os.path.basename(filename)
    )


def account_error(username, password):

    if not username.isalnum():
        return "Username must contain letters and numbers only."

    if len(username) < 3:
        return "Username must have at least 3 characters."

    if len(password) < 4:
        return "Password must have at least 4 characters."

    return None


def handle_client(client, address):

    ip = address[0]

    username = None
    session_token = None

    print(
        "\nClient connected:",
        address
    )

    try:

        while True:

            command = receive_message(
                client
            )

            # -------------------------
            # REGISTER
            # -------------------------

            if command == "REGISTER":

                new_username = receive_message(
                    client
                )

                password = receive_message(
                    client
                )

                error = account_error(
                    new_username,
                    password
                )

                if error:

                    send_message(
                        client,
                        error
                    )

                    continue

                if register_user(
                    new_username,
                    password
                ):

                    save_security_log(
                        new_username,
                        ip,
                        "REGISTER",
                        "SUCCESS"
                    )

                    send_message(
                        client,
                        "Account created successfully."
                    )

                else:

                    send_message(
                        client,
                        "Username already exists."
                    )

                continue

            # -------------------------
            # LOGIN
            # -------------------------

            if command == "LOGIN":

                login_username = receive_message(
                    client
                )

                password = receive_message(
                    client
                )

                if not login_allowed(
                    login_username
                ):

                    send_message(
                        client,
                        "Account temporarily locked. Try again later."
                    )

                    save_security_log(
                        login_username,
                        ip,
                        "LOGIN",
                        "LOCKED"
                    )

                    continue

                if verify_user(
                    login_username,
                    password
                ):

                    reset_login_attempts(
                        login_username
                    )

                    username = login_username

                    role = get_role(
                        username
                    )

                    session_token = create_session(
                        username
                    )

                    save_login(
                        username,
                        ip,
                        "SUCCESS"
                    )

                    save_security_log(
                        username,
                        ip,
                        "LOGIN",
                        "SUCCESS"
                    )

                    send_message(
                        client,
                        "LOGIN_SUCCESS"
                    )

                    send_message(
                        client,
                        session_token
                    )

                    send_message(
                        client,
                        role
                    )

                    print(
                        "Login:",
                        username
                    )

                else:

                    record_failed_login(
                        login_username
                    )

                    save_login(
                        login_username,
                        ip,
                        "FAILED"
                    )

                    save_security_log(
                        login_username,
                        ip,
                        "LOGIN",
                        "FAILED"
                    )

                    send_message(
                        client,
                        "Invalid username or password."
                    )

                continue

            # Commands below require login

            if username is None:

                # Commands that carry data cannot be skipped safely, so
                # close the connection instead of guessing where the next
                # command starts.
                send_message(
                    client,
                    "Please login first."
                )

                break

            if not validate_session(
                session_token
            ):

                send_message(
                    client,
                    "Session expired."
                )

                break

            # -------------------------
            # UPLOAD
            # -------------------------

            if command == "UPLOAD":

                filename = receive_message(
                    client
                )

                recipient = receive_message(
                    client
                )

                file_type = receive_message(
                    client
                )

                original_hash = receive_message(
                    client
                )

                data = receive_bytes(
                    client,
                    True
                )

                valid, message = validate_file(
                    filename,
                    len(data)
                )

                if not valid:

                    send_message(
                        client,
                        message
                    )

                    continue

                if recipient not in get_role_users():

                    send_message(
                        client,
                        "Recipient does not exist."
                    )

                    continue

                actual_hash = file_hash(
                    data
                )

                if actual_hash != original_hash:

                    send_message(
                        client,
                        "Integrity check failed."
                    )

                    save_security_log(
                        username,
                        ip,
                        "UPLOAD_INTEGRITY",
                        "FAILED"
                    )

                    continue

                path = user_file_path(
                    recipient,
                    filename
                )

                # Stored encrypted on the server's disk.
                with open(
                    path,
                    "wb"
                ) as file:

                    file.write(
                        encrypt_data(data)
                    )

                save_transfer(
                    username,
                    ip,
                    "SEND",
                    filename,
                    len(data),
                    file_type,
                    recipient
                )

                save_security_log(
                    username,
                    ip,
                    "SEND_FILE",
                    "SUCCESS"
                )

                send_message(
                    client,
                    "File sent successfully to " + recipient
                )

            # -------------------------
            # DOWNLOAD
            # -------------------------

            elif command == "DOWNLOAD":

                filename = receive_message(
                    client
                )

                filename = os.path.basename(
                    filename
                )

                path = user_file_path(
                    username,
                    filename
                )

                if not os.path.exists(path):

                    send_message(
                        client,
                        "File not found or access denied."
                    )

                    continue

                with open(
                    path,
                    "rb"
                ) as file:

                    encrypted_data = file.read()

                try:

                    data = decrypt_data(
                        encrypted_data
                    )

                except Exception:

                    send_message(
                        client,
                        "File could not be read on the server."
                    )

                    continue

                original_hash = file_hash(
                    data
                )

                send_message(
                    client,
                    "FOUND"
                )

                send_message(
                    client,
                    original_hash
                )

                send_bytes(
                    client,
                    data,
                    True
                )

                file_type = (
                    mimetypes.guess_type(
                        filename
                    )[0]
                    or "Unknown"
                )

                save_transfer(
                    username,
                    ip,
                    "DOWNLOAD",
                    filename,
                    len(data),
                    file_type,
                    username
                )

                save_security_log(
                    username,
                    ip,
                    "DOWNLOAD",
                    "SUCCESS"
                )

            # -------------------------
            # LIST
            # -------------------------

            elif command == "LIST":

                files = []

                for root, dirs, filenames in os.walk(
                    SHARED_FOLDER
                ):

                    for filename in filenames:

                        path = os.path.join(
                            root,
                            filename
                        )

                        size = os.path.getsize(
                            path
                        )

                        file_type = (
                            mimetypes.guess_type(
                                filename
                            )[0]
                            or "Unknown"
                        )

                        files.append(
                            f"{filename} | "
                            f"{size} bytes | "
                            f"{file_type}"
                        )

                if not files:

                    result = "No files available."

                else:

                    result = "\n".join(
                        files
                    )

                send_message(
                    client,
                    result
                )

            # -------------------------
            # MY FILES
            # -------------------------

            elif command == "MY_FILES":

                folder = os.path.join(
                    SHARED_FOLDER,
                    username
                )

                os.makedirs(
                    folder,
                    exist_ok=True
                )

                files = os.listdir(
                    folder
                )

                if not files:

                    result = "No files."

                else:

                    result = "\n".join(
                        files
                    )

                send_message(
                    client,
                    result
                )

            # -------------------------
            # TRANSFER HISTORY
            # -------------------------

            elif command == "TRANSFER_HISTORY":

                send_message(
                    client,
                    get_transfer_history()
                )

            # -------------------------
            # ADMIN
            # -------------------------

            elif command.startswith(
                "ADMIN_"
            ) or command in (
                "HISTORY",
                "SECURITY_LOG"
            ):

                if get_role(
                    username
                ) != "admin":

                    # Read the arguments the client already sent, so the
                    # connection stays in step.
                    arg_count = {
                        "ADMIN_CREATE_USER": 2,
                        "ADMIN_DELETE_USER": 1
                    }.get(command, 0)

                    for _ in range(arg_count):

                        receive_message(client)

                    send_message(
                        client,
                        "Access denied. Admin only."
                    )

                    save_security_log(
                        username,
                        ip,
                        "ADMIN_ACCESS",
                        "DENIED"
                    )

                    continue

                # CREATE USER

                if command == "ADMIN_CREATE_USER":

                    new_user = receive_message(
                        client
                    )

                    new_password = receive_message(
                        client
                    )

                    error = account_error(
                        new_user,
                        new_password
                    )

                    if error:

                        send_message(
                            client,
                            error
                        )

                    elif register_user(
                        new_user,
                        new_password
                    ):

                        send_message(
                            client,
                            "User created successfully."
                        )

                        save_security_log(
                            username,
                            ip,
                            "ADMIN_CREATE_USER",
                            "SUCCESS"
                        )

                    else:

                        send_message(
                            client,
                            "Username already exists."
                        )

                # DELETE USER

                elif command == "ADMIN_DELETE_USER":

                    delete_username = receive_message(
                        client
                    )

                    if delete_user(
                        delete_username
                    ):

                        send_message(
                            client,
                            "User deleted successfully."
                        )

                    else:

                        send_message(
                            client,
                            "Cannot delete user."
                        )

                # USERS

                elif command == "ADMIN_USERS":

                    users = get_users()

                    if users:

                        result = "\n".join(
                            users
                        )

                    else:

                        result = "No users."

                    send_message(
                        client,
                        result
                    )

                # LOGIN HISTORY

                elif command == "HISTORY":

                    send_message(
                        client,
                        get_history()
                    )

                # SECURITY LOG

                elif command == "SECURITY_LOG":

                    send_message(
                        client,
                        get_security_log()
                    )

                else:

                    send_message(
                        client,
                        "Unknown admin command."
                    )

            # -------------------------
            # LOGOUT
            # -------------------------

            elif command == "LOGOUT":

                save_security_log(
                    username,
                    ip,
                    "LOGOUT",
                    "SUCCESS"
                )

                remove_session(
                    session_token
                )

                print(
                    "Logout:",
                    username
                )

                break

            # Unknown command: reply so the client is never left waiting.
            else:

                send_message(
                    client,
                    "Unknown command."
                )

    except Exception as e:

        print(
            "Client error:",
            e
        )

    finally:

        if session_token:

            remove_session(
                session_token
            )

        client.close()

        print(
            "Connection closed:",
            address
        )


def get_role_users():

    from authentication import load_users

    users = load_users()

    return users.keys()


def start_server():

    server = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    server.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1
    )

    server.bind(
        (HOST, PORT)
    )

    server.listen(10)

    context = ssl.SSLContext(
        ssl.PROTOCOL_TLS_SERVER
    )

    context.load_cert_chain(
        CERT_FILE,
        KEY_FILE
    )

    print("==============================")
    print("    SECURE LAN FILE SERVER")
    print("==============================")
    print("Port:", PORT)
    print("TLS: ENABLED")
    print("Waiting for clients...")

    while True:

        client, address = server.accept()

        thread = threading.Thread(
            target=serve_client,
            args=(context, client, address)
        )

        thread.daemon = True

        thread.start()


def serve_client(context, client, address):

    # The TLS handshake runs here, not in the accept loop, so one bad
    # or half-open connection cannot stop the server.
    try:

        secure_client = context.wrap_socket(
            client,
            server_side=True
        )

    except (ssl.SSLError, OSError) as e:

        print(
            "TLS handshake failed:",
            address,
            e
        )

        client.close()

        return

    handle_client(
        secure_client,
        address
    )


if __name__ == "__main__":

    start_server()