import client
import server

if __name__ == "__main__":
    choice = ""
    while choice != "3":
        choice = input("Server - 1, Client - 2, 3 - end: ")
        if choice == "1":
            ip = input("Type IP (only localhost works): ")
            port = int(input("Port: "))
            server.server(ip, port)
        elif choice == "2":
            ip = input("Type IP (only localhost works): ")
            port = int(input("Port: "))
            client.client(ip, port)
