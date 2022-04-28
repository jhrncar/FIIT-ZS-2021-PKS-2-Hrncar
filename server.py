import socket

from crc import CrcCalculator, Crc16


def checksum(full):
    done = full[0:2]
    rest = full[2::]

    check = crc_calculator.calculate_checksum(rest).to_bytes(2, "big")
    if check == done:
        same = True
    else:
        same = False
    return same


def decon_header(full):
    head = str(bin(int.from_bytes(full[2:3], "big")))[2::]
    while len(head) < 8:
        head = "0" + head

    type_ = int(head[0:2], 2)
    code = int(head[2:5], 2)
    status = int(head[5:6])

    return type_, code, status


def send_ack(adress, typ):
    if typ == 0:
        response = int("00011000", 2)  # File, ACK, Status: 0, padding 00
    elif typ == 1:
        response = int("01011000", 2)  # MSG, ACK, Status: 0, padding 00
    else:
        response = int("10010000", 2)  # NET, ACK, Status: 0, padding 00
    response = response.to_bytes(1, "big")
    check = crc_calculator.calculate_checksum(response).to_bytes(2, "big")
    response = check + response
    sock.sendto(response, adress)


def send_nack(adress, typ):
    response = int("01100000", 2)  # MSG, NACK, Status: 0, padding 00
    response = response.to_bytes(1, "big")
    check = crc_calculator.calculate_checksum(response).to_bytes(2, "big")
    response = check + response
    sock.sendto(response, adress)


def return_data(full):
    return full[3::]


def server(UDP_IP, UDP_PORT):
    path = input("Absolute path to storage folder: ")
    path += "\\"
    global crc_calculator, sock
    crc_calculator = CrcCalculator(Crc16.CCITT, True)

    sock = socket.socket(socket.AF_INET,  # Internet
                         socket.SOCK_DGRAM)  # UDP
    sock.bind((UDP_IP, UDP_PORT))

    established = False
    directory = None
    previous_status = None
    requested = False
    last_corrupted = False
    name = b""
    buffer = b""
    counter = 0
    c_ack = 0
    counter_c = 0
    c_nack = 0
    size = 0
    while True:
        if established:
            sock.settimeout(20)
        try:
            data, addr = sock.recvfrom(4096)
        except socket.timeout:
            print("Connection timeout")
            break
        valid = checksum(data)
        frag_type, frag_code, frag_status = decon_header(data)
        if valid:

            if frag_type == 2:
                if frag_code == 1:
                    print("Keep-Alive received, responding...")
                    send_ack(addr, 2)

                elif frag_code == 3:
                    if not established:
                        established = True
                    print("SYN recieved, responding...")
                    send_ack(addr, 2)

                elif frag_code == 4:
                    send_ack(addr, 2)
                    sock.close()
                    break

            elif frag_type == 0 and established:
                if frag_code == 0:
                    directory = None
                    if not requested:
                        print("File transfer starting...")
                        counter = 0
                        c_ack = 0
                        counter_c = 0
                        c_nack = 0
                        requested = True
                    if previous_status != frag_status:
                        name = name + return_data(data)
                        previous_status = frag_status
                        counter += 1
                        print(
                            "New file name data " + str(counter) + " received, sending ACK, size is " + str(
                                len(return_data(data))) + " B")
                    else:
                        counter += 1
                        print(
                            "Duplicated file name data received (ACK was lost), sending ACK, size is " + str(
                                len(return_data(data))) + " B")
                    send_ack(addr, 0)
                    c_ack += 1

                elif frag_code == 1 and requested:
                    if directory is None:
                        directory = open(path + name.decode(), "wb")
                        previous_status = None
                    content = return_data(data)
                    c_ack += 1
                    if previous_status != frag_status:
                        directory.write(content)
                        previous_status = frag_status
                        size += len(content)
                        if not last_corrupted:
                            counter += 1
                            print("New data " + str(counter) + " received, sending ACK, size is " + str(
                                len(content)) + " B")
                        else:
                            print("Corrected data " + str(counter) + " received, sending ACK, size is " + str(
                                len(content)) + " B")
                            last_corrupted = False
                            counter_c += 1
                    else:
                        counter += 1
                        print(
                            "Duplicated data received (ACK was lost), sending ACK, size is " + str(len(content)) + " B")
                    send_ack(addr, 0)

                elif frag_code == 2 and requested:
                    content = return_data(data)
                    counter += 1
                    if directory is None:
                        directory = open(path + name, "wb")
                        previous_status = None
                    if previous_status != frag_status:
                        directory.write(content)
                        previous_status = frag_status
                        size += len(content)
                        print(
                            "New data " + str(counter) + " received, sending ACK, size is " + str(len(content)) + " B")
                    else:
                        print(
                            "Duplicated data received (ACK was lost), sending ACK, size is " + str(len(content)) + " B")

                    c_ack += 1
                    send_ack(addr, 0)
                    directory.close()
                    print("File transfer finished, it has size " + str(
                        size) + " B")
                    print("Absolute path to the transferred file: " + path + name.decode())
                    requested = False
                    previous_status = None
                    name = b""
                    print("Number of sent ACKs for this file: " + str(c_ack))
                    print("Number of sent NACKs for this file: " + str(c_nack))
                    print("Number of received fragments from the client for this file: " + str(counter))
                    print("Number of received fragments from the client for this file: " + str(counter_c))
                    counter = 0
                    c_ack = 0
                    counter_c = 0
                    c_nack = 0
                    size = 0

                elif ((frag_code == 2) or (frag_code == 1)) and not requested:
                    print("Data fragment for unknown file, discarding.." + str(frag_code))

            elif frag_type == 1 and established:
                if frag_code == 1:
                    content = return_data(data)
                    c_ack += 1
                    if previous_status != frag_status:
                        buffer += content
                        previous_status = frag_status
                        if not last_corrupted:
                            counter += 1
                            print("New message data " + str(counter) + " received, sending ACK, size is " + str(
                                len(content)) + " B")
                        else:
                            print("Corrected message data " + str(counter) + " received, sending ACK, size is " + str(
                                len(content)) + " B")
                            last_corrupted = False
                            counter_c += 1
                    else:
                        print("Duplicated message data received (ACK was lost), sending ACK, size is " + str(
                            len(content)) + " B")
                    send_ack(addr, 0)

                elif frag_code == 2:
                    content = return_data(data)
                    counter += 1
                    if previous_status != frag_status:
                        buffer += content
                        previous_status = frag_status
                        print("New message data " + str(counter) + " received, sending ACK, size is " + str(
                            len(content)) + " B")
                        print("Received message is: " + buffer.decode())
                        print("Size of received message is: " + str(len(buffer)))
                    else:
                        print("Duplicated message data received (ACK was lost), sending ACK, size is " + str(
                            len(content)) + " B")
                    send_ack(addr, 0)
                    c_ack += 1

                    buffer = b""
                    previous_status = None
                    print("Number of sent ACKs for this message: " + str(c_ack))
                    print("Number of sent NACKs for this message: " + str(c_nack))
                    print("Number of received fragments from the client for this message: " + str(counter))
                    print("Number of received corrupted fragments from the client for this message: " + str(counter_c))
                    counter = 0
                    c_ack = 0
                    counter_c = 0
                    c_nack = 0

        else:
            counter += 1
            print("Data " + str(counter) + " was corrupted, sending NACK")
            last_corrupted = True
            send_nack(addr, frag_type)
            c_nack += 1
