import os
import struct
import hashlib

from security import validate_file


def send_message(sock, message):

    data = message.encode()

    sock.sendall(struct.pack("!I", len(data)))
    sock.sendall(data)


def receive_exact(sock, size):

    data = b""

    while len(data) < size:

        packet = sock.recv(
            min(4096, size - len(data))
        )

        if not packet:
            raise ConnectionError("Connection closed.")

        data += packet

    return data


def receive_message(sock):

    size_data = receive_exact(sock, 4)

    size = struct.unpack("!I", size_data)[0]

    data = receive_exact(sock, size)

    return data.decode()


def send_bytes(sock, data, progress=False):

    total = len(data)

    sock.sendall(struct.pack("!Q", total))

    sent = 0

    while sent < total:

        chunk = data[sent:sent + 4096]

        sock.sendall(chunk)

        sent += len(chunk)

        if progress:
            show_progress(sent, total)

    if progress:
        print()


def receive_bytes(sock, progress=False):

    size_data = receive_exact(sock, 8)

    total = struct.unpack("!Q", size_data)[0]

    data = bytearray()

    received = 0

    while received < total:

        chunk = sock.recv(
            min(4096, total - received)
        )

        if not chunk:
            raise ConnectionError("Connection closed.")

        data.extend(chunk)

        received += len(chunk)

        if progress:
            show_progress(received, total)

    if progress:
        print()

    return bytes(data)


def show_progress(current, total):

    percent = (current / total) * 100

    length = 30

    filled = int(length * current / total)

    bar = "#" * filled + "-" * (length - filled)

    print(
        f"\rProgress: [{bar}] {percent:.1f}%",
        end=""
    )


def calculate_hash(data):

    return hashlib.sha256(data).hexdigest()


def upload_file(sock, filepath, recipient):

    if not os.path.exists(filepath):

        print("File not found.")
        return

    filename = os.path.basename(filepath)

    with open(filepath, "rb") as file:
        data = file.read()

    size = len(data)

    extension = os.path.splitext(filename)[1].lower()

    valid, message = validate_file(filename, size)

    if not valid:

        print(message)
        return

    file_hash = calculate_hash(data)

    send_message(sock, "UPLOAD")

    send_message(sock, filename)

    send_message(sock, recipient)

    send_message(sock, extension)

    send_message(sock, file_hash)

    print("\nSending:", filename)
    print("Size:", size, "bytes")

    # The connection is already TLS-encrypted. The server encrypts the
    # file again before storing it, so only the server needs the key.
    send_bytes(sock, data, True)

    print(receive_message(sock))


def download_file(sock, filename):

    send_message(sock, "DOWNLOAD")

    send_message(sock, filename)

    response = receive_message(sock)

    if response != "FOUND":

        print(response)
        return

    original_hash = receive_message(sock)

    data = receive_bytes(sock, True)

    new_hash = calculate_hash(data)

    if original_hash != new_hash:

        print("\nIntegrity check failed!")
        return

    with open(filename, "wb") as file:
        file.write(data)

    print("\nDownloaded:", filename)
    print("Integrity verified.")


def list_files(sock):

    send_message(sock, "LIST")

    response = receive_message(sock)

    print("\n========== FILES ==========")
    print(response)
    print("===========================")


def get_my_files(sock):

    send_message(sock, "MY_FILES")

    response = receive_message(sock)

    print("\n========== MY FILES ==========")
    print(response)
    print("==============================")