import os
import socket
import getpass
import ssl

from file_transfer import (
    send_message,
    receive_message,
    upload_file,
    download_file,
    list_files,
    get_my_files
)

from admin import admin_menu


PORT = 5000

# Copy server.crt from the server folder into the client folder.
# The client only connects to a server presenting this exact certificate.
PINNED_CERT = "server.crt"


def load_pinned_cert():

    if not os.path.exists(PINNED_CERT):
        return None

    with open(PINNED_CERT, "r") as file:
        return ssl.PEM_cert_to_DER_cert(file.read())


def register(sock):

    print("\n========== CREATE ACCOUNT ==========")

    username = input("Username: ")
    password = getpass.getpass("Password: ")

    send_message(sock, "REGISTER")

    send_message(sock, username)

    send_message(sock, password)

    print(receive_message(sock))


def login(sock):

    print("\n========== LOGIN ==========")

    username = input("Username: ")

    password = getpass.getpass("Password: ")

    send_message(sock, "LOGIN")

    send_message(sock, username)

    send_message(sock, password)

    response = receive_message(sock)

    if response != "LOGIN_SUCCESS":

        print(response)

        return False, None, None

    token = receive_message(sock)

    role = receive_message(sock)

    print("\nLogin successful!")

    print("Role:", role)

    return True, token, role


def user_menu(sock):

    while True:

        print("\n==============================")
        print("       SECURE FILE SHARE")
        print("==============================")

        print("1. Send File")
        print("2. Download File")
        print("3. List Files")
        print("4. My Files")
        print("5. Transfer History")
        print("6. Logout")

        choice = input("\nEnter choice: ")

        if choice == "1":

            filepath = input("Enter file path: ")

            recipient = input(
                "Enter recipient username: "
            )

            upload_file(
                sock,
                filepath,
                recipient
            )

        elif choice == "2":

            filename = input(
                "Enter filename: "
            )

            download_file(
                sock,
                filename
            )

        elif choice == "3":

            list_files(sock)

        elif choice == "4":

            get_my_files(sock)

        elif choice == "5":

            send_message(
                sock,
                "TRANSFER_HISTORY"
            )

            print(
                receive_message(sock)
            )

        elif choice == "6":

            send_message(
                sock,
                "LOGOUT"
            )

            print("Logged out.")

            break

        else:

            print("Invalid choice.")


def main_menu(sock):

    while True:

        print("\n==============================")
        print("    SECURE LAN FILE SHARING")
        print("==============================")

        print("1. Login")
        print("2. Create Account")
        print("3. Exit")

        choice = input("\nEnter choice: ")

        if choice == "1":

            success, token, role = login(sock)

            if success:

                if role == "admin":

                    admin_menu(sock)

                else:

                    user_menu(sock)

                return True

        elif choice == "2":

            register(sock)

        elif choice == "3":

            return False

        else:

            print("Invalid choice.")


def start_client():

    pinned_cert = load_pinned_cert()

    if pinned_cert is None:

        print(
            "\nMissing server.crt. Copy it from the server folder "
            "into this folder, then try again."
        )

        return

    server_ip = input(
        "Enter Server IP: "
    )

    client = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    context = ssl.create_default_context()

    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    secure_client = context.wrap_socket(
        client,
        server_hostname=server_ip
    )

    try:

        secure_client.connect(
            (server_ip, PORT)
        )

        # Certificate pinning: the server must present our copy of server.crt.
        if secure_client.getpeercert(binary_form=True) != pinned_cert:

            print(
                "\nServer certificate does not match server.crt. "
                "Connection refused."
            )

            return

        print("\nSecure connection established.")

        main_menu(secure_client)

    except ConnectionRefusedError:

        print(
            "\nCould not connect to server."
        )

    except Exception as e:

        print("\nError:", e)

    finally:

        secure_client.close()


if __name__ == "__main__":
    start_client()