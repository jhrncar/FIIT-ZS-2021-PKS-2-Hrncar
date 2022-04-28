import socket
import time

from crc import CrcCalculator, Crc16
import threading


def checksum(full):
    done = full[0:2]
    rest = full[2::]

    check = crc_calculator.calculate_checksum(rest).to_bytes(2, "big")
    if check == done:
        return True
    else:
        return False


def decon_header(data):
    head = str(bin(int.from_bytes(data[2:3], "big")))[2::]
    while len(head) < 8:
        head = "0" + head

    type_ = int(head[0:2], 2)
    code = int(head[2:5], 2)
    status = int(head[5:6])

    return type_, code, status


def establish():
    header = int("10011100", 2)  # Network, SYN, Status: 1, padding 00
    header = header.to_bytes(1, "big")
    check = crc_calculator.calculate_checksum(header).to_bytes(2, "big")
    msg = check + header
    sock.sendto(msg, (UDP_IP, UDP_PORT))

    data = None
    tries = 0
    while data is None and tries < 5:
        sock.settimeout(5)
        try:
            tries += 1
            data, addr = sock.recvfrom(4096)
        except socket.timeout:
            sock.sendto(msg, (UDP_IP,
                              UDP_PORT))  # ak sa strati ACK, 5 krat opakujem poslanie. Ak sa strati SYN, znamena to pre mna to iste
            print("retrying")
    if data is None:
        print("failed")
        return False
    valid = checksum(data)

    if valid:
        frag_type, frag_code, frag_status = decon_header(data)
        if frag_type == 2 and frag_code == 2:
            print("Connection established")
            return True


def send_file(frag_length, path):
    previous_status = "1"
    status = None
    name = path.split("\\")[-1]
    name_copy = name
    counter = 0
    c_ack = 0
    c_nack = 0

    while len(name_copy) > frag_length:
        name_copy = name_copy.encode()
        prepared = name_copy[0:frag_length]
        name_copy = name_copy[frag_length::]
        if previous_status == "1":
            status = "0"
            previous_status = "0"
        elif previous_status == "0":
            status = "1"
            previous_status = "1"
        header = int("00000" + status + "00", 2)  # file, WRQ, Status: 1, padding 00
        header = header.to_bytes(1, "big")
        msg = header + prepared
        check = crc_calculator.calculate_checksum(msg).to_bytes(2, "big")
        msg = check + msg
        sock.sendto(msg, (UDP_IP, UDP_PORT))
        counter += 1

        data = None
        while data is None:
            sock.settimeout(5)
            try:
                data, addr = sock.recvfrom(4096)
                c_ack += 1
            except socket.timeout:
                sock.sendto(msg, (UDP_IP, UDP_PORT))
                counter += 1

    else:
        prepared = name_copy
        prepared = prepared.encode()
        if previous_status == "1":
            status = "0"
            previous_status = "0"
        elif previous_status == "0":
            status = "1"
            previous_status = "1"
        header = int("00000" + status + "00", 2)  # file, WRQ, Status: 1, padding 00
        header = header.to_bytes(1, "big")
        msg = header + prepared
        check = crc_calculator.calculate_checksum(msg).to_bytes(2, "big")
        msg = check + msg
        sock.sendto(msg, (UDP_IP, UDP_PORT))
        counter += 1

        data = None
        while data is None:
            sock.settimeout(5)
            try:
                data, addr = sock.recvfrom(4096)
                c_ack += 1
            except socket.timeout:
                sock.sendto(msg, (UDP_IP, UDP_PORT))
                counter += 1

    valid = checksum(data)
    previous_status = "1"
    status = None

    if valid:
        frag_type, frag_code, frag_status = decon_header(data)
        if frag_type == 0 and frag_code == 3:
            file = open(path, "rb").read()
            size = len(file)

            while len(file) > frag_length:
                prepared = file[0:frag_length]
                file = file[frag_length::]
                if previous_status == "1":
                    status = "0"
                    previous_status = "0"
                elif previous_status == "0":
                    status = "1"
                    previous_status = "1"

                header = int("00001" + status + "00", 2)  # file, DATA, Status: ?, padding 00
                header = header.to_bytes(1, "big")
                check = (crc_calculator.calculate_checksum(header + prepared)).to_bytes(2, "big")
                if counter % 100 == 0 and counter != 0:
                    prepared_copy = int.from_bytes(prepared, "big")
                    prepared_copy = prepared_copy >> 1
                    prepared_copy = prepared_copy.to_bytes(frag_length, "big")
                    msg = check + header + prepared_copy
                else:
                    msg = check + header + prepared
                sock.sendto(msg, (UDP_IP, UDP_PORT))
                counter += 1

                data = None
                while data is None:
                    sock.settimeout(5)
                    try:
                        data, addr = sock.recvfrom(4096)

                        frag_type, frag_code, frag_status = decon_header(data)

                        if frag_code == 4:
                            check = crc_calculator.calculate_checksum(header + prepared).to_bytes(2, "big")
                            msg = check + header + prepared
                            sock.sendto(msg, (UDP_IP, UDP_PORT))
                            counter += 1
                            data = None
                            c_nack += 1
                        else:
                            c_ack += 1
                    except socket.timeout:
                        sock.sendto(msg, (UDP_IP, UDP_PORT))
                        counter += 1

            else:
                if len(file) > 0:
                    prepared = file
                    if previous_status == "1":
                        status = "0"
                        previous_status = "0"
                    elif previous_status == "0":
                        status = "1"
                        previous_status = "1"

                    header = int("00010" + status + "00", 2)  # file, DATA END, Status: ?, padding 00
                    header = header.to_bytes(1, "big")
                    msg = header + prepared
                    check = crc_calculator.calculate_checksum(msg).to_bytes(2, "big")
                    msg = check + msg
                    sock.sendto(msg, (UDP_IP, UDP_PORT))
                    counter += 1

                    data = None
                    while data is None:
                        sock.settimeout(5)
                        try:
                            data, addr = sock.recvfrom(4096)
                            frag_type, frag_code, frag_status = decon_header(data)

                            if frag_code == 4:
                                sock.sendto(msg, (UDP_IP, UDP_PORT))
                                counter += 1
                                c_nack += 1
                            else:
                                c_ack += 1
                        except socket.timeout:
                            sock.sendto(msg, (UDP_IP, UDP_PORT))
                            counter += 1

                print("Number of sent fragments for this file: " + str(counter))
                print("Number of received ACKs from the server for this file: " + str(c_ack))
                print("Number of received NACKs from the server for this file: " + str(c_nack))
                print("Maximum fragment size for this transfer was set to " + str(frag_length))
                print("Size of sent file was: " + str(size))


def send_msg(frag_length, content):
    previous_status = "1"
    counter = 0
    c_ack = 0
    c_nack = 0
    status = None
    content = content.encode()
    size = len(content)

    while len(content) > frag_length:
        prepared = content[0:frag_length]
        content = content[frag_length::]
        if previous_status == "1":
            status = "0"
            previous_status = "0"
        elif previous_status == "0":
            status = "1"
            previous_status = "1"
        header = int("01001" + status + "00", 2)  # msg, DATA, Status: ?, padding 00
        header = header.to_bytes(1, "big")
        check = (crc_calculator.calculate_checksum(header + prepared)).to_bytes(2, "big")
        if counter % 5 == 0 and counter != 0:
            prepared_copy = int.from_bytes(prepared, "big")
            prepared_copy = prepared_copy >> 1
            prepared_copy = prepared_copy.to_bytes(frag_length, "big")
            msg = check + header + prepared_copy
        else:
            msg = check + header + prepared
        sock.sendto(msg, (UDP_IP, UDP_PORT))
        counter += 1

        data = None
        while data is None:
            sock.settimeout(5)
            try:
                data, addr = sock.recvfrom(4096)

                frag_type, frag_code, frag_status = decon_header(data)
                if frag_code == 4:
                    check = crc_calculator.calculate_checksum(header + prepared).to_bytes(2, "big")
                    msg = check + header + prepared
                    sock.sendto(msg, (UDP_IP, UDP_PORT))
                    counter += 1
                    data = None
                    c_nack += 1
                else:
                    c_ack += 1
            except socket.timeout:
                sock.sendto(msg, (UDP_IP, UDP_PORT))
                counter += 1
    else:
        prepared = content
        if previous_status == "1":
            status = "0"
            previous_status = "0"
        elif previous_status == "0":
            status = "1"
            previous_status = "1"
        header = int("01010" + status + "00", 2)  # file, DATA END, Status: ?, padding 00
        header = header.to_bytes(1, "big")
        msg = header + prepared
        check = crc_calculator.calculate_checksum(msg).to_bytes(2, "big")
        msg = check + msg
        sock.sendto(msg, (UDP_IP, UDP_PORT))
        counter += 1

        data = None
        while data is None:
            sock.settimeout(5)
            try:
                data, addr = sock.recvfrom(4096)

                frag_type, frag_code, frag_status = decon_header(data)
                if frag_type == 1 and frag_code == 4:
                    sock.sendto(msg, (UDP_IP, UDP_PORT))
                    counter += 1
                    c_nack += 1
                else:
                    c_ack += 1
            except socket.timeout:
                sock.sendto(msg, (UDP_IP, UDP_PORT))
                counter += 1
    print("Number of sent fragments for this message: " + str(counter))
    print("Number of received ACKs from the server for this message: " + str(c_ack))
    print("Number of received NACKs from the server for this message: " + str(c_nack))
    print("Size of sent message was: " + str(size))


def finish():
    header = int("10100100", 2)  # Network, FIN, Status: 1, padding 00
    header = header.to_bytes(1, "big")
    check = crc_calculator.calculate_checksum(header).to_bytes(2, "big")
    msg = check + header

    data = None
    tries = 0
    while data is None and tries < 5:
        sock.sendto(msg, (UDP_IP,
                          UDP_PORT))
        sock.settimeout(5)
        try:
            tries += 1
            data, addr = sock.recvfrom(4096)

        except socket.timeout:
            print("retrying")
    if data is None:
        print("forced shutdown")
        sock.close()
        return
    valid = checksum(data)
    frag_type, frag_code, frag_status = decon_header(data)
    if valid:

        if frag_type == 2 and frag_code == 2:
            print("Connection terminated")
            sock.close()
            return


class KeepAlive:
    work = False
    alive = True
    received = True

    def __init__(self, work, alive):
        self.work = work
        self.alive = alive

    def keep_alive(self):
        try:
            while self.work:
                header = int("10001100", 2)  # Network, KA, Status: 1, padding 00
                header = header.to_bytes(1, "big")
                check = crc_calculator.calculate_checksum(header).to_bytes(2, "big")
                msg = check + header
                self.received = False

                data = None
                tries = 0
                while data is None and tries < 5:
                    sock.sendto(msg, (UDP_IP, UDP_PORT))
                    tries += 1
                    sock.settimeout(5)
                    try:
                        data, addr = sock.recvfrom(4096)
                    except socket.timeout:
                        print("retrying")
                        if tries == 5:
                            print("\nKEEP ALIVE FAILED, ANY INPUT WON'T MATTER")
                            sock.close()
                            self.alive = False
                            self.received = False
                            break
                if not self.alive:
                    break
                self.received = True
                time.sleep(10)
        except ConnectionResetError:
            print("\nKEEP ALIVE FAILED, ANY INPUT WON'T MATTER")
            self.alive = False
            sock.close()
            self.received = False


def client(ip, port):
    global crc_calculator, sock, UDP_IP, UDP_PORT
    crc_calculator = CrcCalculator(Crc16.CCITT, True)
    UDP_IP = ip
    UDP_PORT = port
    sock = socket.socket(socket.AF_INET,  # Internet
                         socket.SOCK_DGRAM)  # UDP
    established = establish()
    action = ""
    keep_alive = KeepAlive(True, True)
    keep_alive_thread = threading.Thread(target=keep_alive.keep_alive)
    keep_alive_thread.start()
    if established:
        while action != "3":
            try:
                if keep_alive.alive:
                    action = input("1 - send message, 2 - send file, 3 - end: ")
                    if keep_alive.alive:
                        if action == "1":
                            fragment = int(input("Fragment length (1 - 1469): "))
                            if fragment > 1469:
                                fragment = 1469
                            message = input("Message: ")
                            keep_alive.work = False
                            keep_alive_thread.join()
                            send_msg(fragment, message)
                            print("Sent successfully")
                            keep_alive.work = True
                            keep_alive_thread = threading.Thread(target=keep_alive.keep_alive)
                            keep_alive_thread.start()
                        elif action == "2":
                            fragment = int(input("Fragment length (1 - 1469): "))
                            if fragment > 1469:
                                fragment = 1469
                            f_name = input(
                                "Absolute path to the file (with backslashes as separators): ")
                            print("Transfer starting")
                            keep_alive.work = False
                            keep_alive_thread.join()
                            send_file(fragment, f_name)
                            print("Sent successfully")
                            keep_alive.work = True
                            keep_alive_thread = threading.Thread(target=keep_alive.keep_alive)
                            keep_alive_thread.start()
                        elif action == "3":
                            keep_alive.work = False
                            keep_alive_thread.join()
                            finish()
                    else:
                        print("Resetting program, wait please...")
                        keep_alive_thread.join()
                        break
            except OSError:
                print("Resetting program, wait please..")
                keep_alive_thread.join()
                break
