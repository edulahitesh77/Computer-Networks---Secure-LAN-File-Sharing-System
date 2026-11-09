from file_transfer import send_message, receive_message


def admin_menu(sock):

    while True:

        print("\n==============================")
        print("         ADMIN PANEL")
        print("==============================")
        print("1. Create User")
        print("2. Delete User")
        print("3. View Users")
        print("4. Login History")
        print("5. Transfer History")
        print("6. Security Log")
        print("7. Logout")

        choice = input("\nEnter choice: ")

        if choice == "1":

            username = input("New username: ")
            password = input("New password: ")

            send_message(sock, "ADMIN_CREATE_USER")
            send_message(sock, username)
            send_message(sock, password)

            print(receive_message(sock))

        elif choice == "2":

            username = input("Username to delete: ")

            send_message(sock, "ADMIN_DELETE_USER")
            send_message(sock, username)

            print(receive_message(sock))

        elif choice == "3":

            send_message(sock, "ADMIN_USERS")

            print("\n========== USERS ==========")
            print(receive_message(sock))
            print("===========================")

        elif choice == "4":

            send_message(sock, "HISTORY")

            print("\n========== LOGIN HISTORY ==========")
            print(receive_message(sock))
            print("===================================")

        elif choice == "5":

            send_message(sock, "TRANSFER_HISTORY")

            print("\n========== TRANSFER HISTORY ==========")
            print(receive_message(sock))
            print("=======================================")

        elif choice == "6":

            send_message(sock, "SECURITY_LOG")

            print("\n========== SECURITY LOG ==========")
            print(receive_message(sock))
            print("==================================")

        elif choice == "7":

            send_message(sock, "LOGOUT")

            print("Logged out.")

            break

        else:

            print("Invalid choice.")