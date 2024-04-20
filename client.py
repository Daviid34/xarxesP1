#!/usr/bin/env python3

import select
import socket
import struct
import sys
import time
import os
import signal

SUBS_REQ = 0x00
SUBS_ACK = 0x01
SUBS_REJ = 0x02
SUBS_INFO = 0x03
INFO_ACK = 0x04
SUBS_NACK = 0x05

HELLO = 0x10
HELLO_REJ = 0x11

DISCONNECTED = 0xa0
NOT_SUBSCRIBED = 0xa1
WAIT_ACK_SUBS = 0xa2
WAIT_ACK_INFO = 0xa4
SUBSCRIBED = 0xa5
SEND_HELLO = 0xa6

next_state = 0xa1

SEND_DATA = 0x20
SET_DATA = 0x21
GET_DATA = 0x22
DATA_ACK = 0x23
DATA_NACK = 0x24
DATA_REJ = 0x25

client_config = {}

server_data = {}

elements_dict = {}

tries = 0

no_response = 0

pid = 0

debug = False


def sig_int(sig, frame):
    global sock_udp, sock_tcp, sock_tcp2
    _ = sig, frame
    if pid == 0:
        sock_udp.close()
        if debug:
            print(f"{time.strftime('%H:%M:%S')}: DEBUG  => Tancat socket UDP per la comunicació amb el servidor")
        print(f"{time.strftime('%H:%M:%S')}: MSG. => Finalització per ^C")
        exit(0)
    else:
        close_tcp()
        exit(0)


def sig_usr1(sig, frame):
    global sock_tcp, sock_tcp2
    _ = sig, frame
    close_tcp()
    exit(0)


def close_tcp():
    global sock_tcp, sock_tcp2
    if "sock_tcp2" in globals():
        sock_tcp2.close()
        if debug:
            print(f"{time.strftime('%H:%M:%S')}: DEBUG  => Tancat socket TCP per la comunicació amb el servidor")
    if "sock_tcp" in globals():
        sock_tcp.close()
        if debug:
            print(f"{time.strftime('%H:%M:%S')}: DEBUG  => Tancat socket TCP per la comunicació amb el servidor")


def sig_usr2(sig, frame):
    global tries
    _ = sig, frame
    u = 2
    time.sleep(u)
    tries = 0
    new_sub_process()


def setup_tcp():
    global sock_tcp
    sock_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock_tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock_tcp.bind((client_config['Server'], int(client_config['Local-TCP'])))
    sock_tcp.listen(1)


def debug_package2(buffer, flag):
    lon_bytes = len(buffer)
    command = get_command_name(buffer[0])
    mac = buffer[1:14].decode()
    random_num = buffer[14:23].decode()
    device = buffer[23:31].decode().strip('\x00')
    index = buffer[31:38].find(b'\x00')
    value = buffer[31:(31 + index)].decode()
    index2 = buffer[(31 + index):].find(b'\x00')
    info = buffer[(31 + index):index2].decode()
    if flag == 0:
        print(f"{time.strftime('%H:%M:%S')}: DEBUG.  => Enviat: bytes={lon_bytes}, comanda={command}, mac={mac}, "
              f"rndm={random_num}, element={device}, valor={value}, info={info}")
    else:
        print(f"{time.strftime('%H:%M:%S')}: DEBUG.  => Rebut: bytes={lon_bytes}, comanda={command}, mac={mac}, "
              f"rndm={random_num}, element={device}, valor={value}, info={info}")


def read_terminal():
    global sock_tcp
    w = 3
    inputs = [sys.stdin, sock_tcp]
    setup_elements()
    print_stat()
    while True:
        readable, _, _ = select.select(inputs, [], [])
        for connection in readable:
            if connection is sys.stdin:
                command = input()
                command = command.split()
                if not command:
                    pass
                elif command[0].lower() == "stat":
                    print_stat()

                elif command[0].lower() == "set":
                    set_command(command)

                elif command[0].lower() == "quit":
                    os.kill(os.getppid(), signal.SIGINT)
                    os.kill(os.getpid(), signal.SIGINT)

                elif command[0].lower() == "send":
                    send_command(command)

                else:
                    print(f"{time.strftime('%H:%M:%S')}: MSG.  => Comanda incorrecta ({command[0]})")
            else:
                connection, server = sock_tcp.accept()
                connection.settimeout(w)
                buffer = connection.recv(1500)
                if debug:
                    debug_package2(buffer, 1)
                connection.settimeout(None)
                server_request_treatment(buffer, connection, server)


def server_request_treatment(buffer, connection, serv):
    try:
        type_request = buffer[0]
        device = buffer[23:31].decode().strip('\x00')
        index = buffer[31:38].find(b'\x00')
        value = buffer[31:(31 + index)].decode()
        if check_server_data(buffer, serv):
            if device in elements_dict:
                if type_request == SET_DATA and device[-1] == 'I':
                    elements_dict[device] = value
                    data_ack = create_data_ack(device, 0)
                    connection.send(data_ack)
                    if debug:
                        debug_package2(data_ack, 0)

                elif type_request == GET_DATA:
                    data_ack = create_data_ack(device, 1)
                    connection.send(data_ack)
                    if debug:
                        debug_package2(data_ack, 0)
                else:
                    data_nack = create_data_nack(device, value)
                    connection.send(data_nack)
                    if debug:
                        print(f"{time.strftime('%H:%M:%S')}: DEBUG => Error paquet rebut. Element: "
                              f"{device} és sensor i no permet establir el seu valor")
                        debug_package2(data_nack, 0)
            else:
                data_nack = create_data_nack(device, value)
                connection.send(data_nack)
                if debug:
                    debug_package2(data_nack, 0)
        else:
            data_rej = create_data_rej(device, value)
            connection.send(data_rej)
            if debug:
                debug_package2(data_rej, 0)
            os.kill(os.getppid(), signal.SIGUSR2)
            exit(0)
    finally:
        connection.close()


def create_data_rej(device, value):
    info = "Discrepancia amb la identificació del servidor"
    data_rej = struct.pack('1B13s9s8s7s80s', DATA_REJ, client_config['MAC'].encode(),
                           server_data['random'].encode(), device.encode(), value.encode(),
                           info.encode())
    return data_rej


def create_data_nack(device, value):
    info = "Discrepancia amb la identificació del dispositiu"
    data_nack = struct.pack('1B13s9s8s7s80s', DATA_NACK, client_config['MAC'].encode(),
                            server_data['random'].encode(), device.encode(), value.encode(),
                            info.encode())
    return data_nack


def send_command(command):
    w = 3
    if command[1] not in elements_dict:
        print(f"{time.strftime('%H:%M:%S')} MSG.  => Element {command[1]} no pertany al controlador")
    else:
        send_data_pdu = create_data_send(command[1])
        connect_tcp()
        print(f"{time.strftime('%H:%M:%S')}: MSG.  => Obert port TCP {server_data['TCP-port']} per la "
              f"comunicació amb el servidor")
        sock_tcp2.send(send_data_pdu)
        if debug:
            debug_package2(send_data_pdu, 0)
        try:
            sock_tcp2.settimeout(w)
            server_answer = sock_tcp2.recv(1500)
            if debug:
                debug_package2(server_answer, 1)
            serv = sock_tcp2.getpeername()
            data_treatment(server_answer, serv)  # Al ser tcp ja sabem quina es la ip del server
        except socket.timeout:
            if debug:
                print(f"{time.strftime('%H:%M:%S')} DEBUG  => No s'ha rebut resposta del servidor "
                      f"per la comunicació TCP")
        sock_tcp2.close()


def set_command(command):
    if len(command) != 3:
        print(f"{time.strftime('%H:%M:%S')} MSG.  => Error de sintàxi. (set <element> <valor>)")

    elif command[1] not in elements_dict:
        print(f"{time.strftime('%H:%M:%S')} MSG.  => Element {command[1]} no pertany al controlador")

    else:
        elements_dict[command[1]] = command[2]


def data_treatment(buffer, serv):
    global tries
    type_package = buffer[0]
    device = buffer[23:31].decode()
    index = buffer[31:].find(b'\x00')
    value = buffer[31:(32 + index)].decode()
    if type_package == DATA_REJ or not check_server_data(buffer, serv):
        os.kill(os.getppid(), signal.SIGUSR2)
        sock_tcp2.close()
        exit(0)
    if device not in elements_dict and debug:
        print(f"{time.strftime('%H:%M:%S')} DEBUG => Error en les dades d'identificació del element del controlador"
              f" (rebut element: {device}, valor: {value})")


def new_sub_process():
    global next_state
    next_state = NOT_SUBSCRIBED
    subscribe_process()


def connect_tcp():
    global sock_tcp2
    sock_tcp2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock_tcp2.connect((client_config['Server'], int(server_data['TCP-port'])))


def create_data_send(element):
    info = ""
    value = elements_dict[element]
    data_pdu = struct.pack('1B13s9s8s7s80s', SEND_DATA, client_config['MAC'].encode(),
                           server_data['random'].encode(), element.encode(), value.encode(),
                           info.encode())
    return data_pdu


def create_data_ack(element, flag):
    if flag == 0:
        info = "Valor llegit correctament"
    else:
        info = "Valor enviat correctament"
    value = elements_dict[element]
    data_pdu = struct.pack('1B13s9s8s7s80s', DATA_ACK, client_config['MAC'].encode(),
                           server_data['random'].encode(), element.encode(), value.encode(),
                           info.encode())
    return data_pdu


def print_stat():
    print("******************** DADES CONTROLADOR *********************")
    print(f" MAC: {client_config['MAC']}, Nom: {client_config['Name']}, Situació: {client_config['Situation']}\n")
    print(f"    Estat: SEND_HELLO\n")
    print(f"     Dispos.      valor")
    print("     -------      -----")
    for element, value in elements_dict.items():
        print(f"     {element}       {value}")
    print("***********************************************************")


def setup_elements():
    elements = client_config['Elements'].split(';')
    for element in elements:
        elements_dict[element] = "NONE"


def process_config(file):
    try:
        config = open(file, 'r')
        for line in config.readlines():
            split_line = line.split()
            client_config[split_line[0]] = split_line[2]
        if debug:
            print(f"{time.strftime('%H:%M:%S')}: DEBUG.  => Llegits paràmetres arxius de configuració")
    except FileNotFoundError:
        print(f"{time.strftime('%H:%M:%S')}: ERR0R.  => No es pot obrir l'arxiu de configuració {file}")


def send_hello(v):
    global no_response
    hello_pdu = create_hello()
    time.sleep(v)
    sock_udp.sendto(hello_pdu, (client_config['Server'], int(client_config['Srv-UDP'])))
    if debug:
        debug_package(hello_pdu, 0)
    sock_udp.settimeout(v)
    try:
        buffer, check_serv = sock_udp.recvfrom(1500)
        if debug:
            debug_package(hello_pdu, 1)
        if not check_server_data(buffer, check_serv) or get_command_name(buffer[0]) == "HELLO_REJ":
            hello_rej_pdu = create_hello_rej()
            sock_udp.sendto(hello_rej_pdu, (client_config['Server'], int(client_config['Srv-UDP'])))
            if debug:
                if get_command_name(buffer[0]) == "HELLO_REJ":
                    print(f"{time.strftime('%H:%M:%S')}: DEBUG.  => Rebut paquet de rebuig de HELLO")
                debug_package(hello_rej_pdu, 0)
            return -1
        no_response = 0
    except socket.timeout:
        no_response += 1
    return 0


def create_hello_rej():
    data = client_config['Name'] + "," + client_config['Situation']
    hello_rej_pdu = struct.pack('1B13s9s80s', HELLO_REJ, client_config['MAC'].encode(),
                                server_data['random'].encode(),
                                data.encode())
    return hello_rej_pdu


def check_server_data(pdu, serv):
    mac = pdu[1:14].decode()
    rand_num = pdu[14:23].decode()
    if mac == server_data['MAC'] and rand_num == server_data['random'] and serv[0] == server_data['IP']:
        return True
    if rand_num != server_data['random']:
        print(f"{time.strftime('%H:%M:%S')}: ALERT  => Error en el valor del camp rndm "
              f"(rebut: {rand_num}, esperat: {server_data['random']})")
    else:
        print(f"{time.strftime('%H:%M:%S')}: ALERT  => Error en les dades d'identificació del servidor "
              f"(rebut ip: {serv[0]}, mac: {mac})")
    return False


def wait_ack_subs_state():
    global next_state, sock_udp, sock_udp2
    t = 1
    n = 7
    p = 3
    q = 3
    packets_sent = 0
    while packets_sent < n:
        try:
            if packets_sent < p:
                sock_udp.settimeout(t)
            else:
                new_timeout = t + (packets_sent + 1 - p)
                if new_timeout >= t * q:
                    sock_udp.settimeout(t * q)
                else:
                    sock_udp.settimeout(new_timeout)
            subs_ack_pdu, server = sock_udp.recvfrom(1500)
            if debug:
                debug_package(subs_ack_pdu, 1)
            sock_udp.settimeout(None)
            server_data['IP'] = server[0]
            return subs_ack_treatment(subs_ack_pdu)
        except socket.error or socket.timeout:
            packets_sent += 1
            sub_req_pdu = create_subs_req()
            sock_udp.sendto(sub_req_pdu, (client_config['Server'], int(client_config['Srv-UDP'])))
            if debug:
                debug_package(sub_req_pdu, 0)

    return NOT_SUBSCRIBED


def subs_ack_treatment(buffer):
    global tries, sock_udp2
    type_package = buffer[0]
    mac_server = buffer[1:14]
    random_num = buffer[14:23]
    index = buffer[23:].find(b'\x00')
    new_port = buffer[23:(24 + index)]
    data_index = buffer[29:].find(b'\x00')
    data = buffer[29:(30 + data_index)]
    sock_udp2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if type_package == SUBS_ACK:
        server_data['MAC'] = mac_server.decode()
        server_data['random'] = random_num.decode()
        data = client_config['Local-TCP'] + ',' + client_config['Elements']
        packet = struct.pack('1B13s9s80s', SUBS_INFO, client_config['MAC'].encode(), random_num,
                             data.encode())
        sock_udp2.sendto(packet, (client_config['Server'], int(new_port.decode().strip('\x00'))))
        if debug:
            debug_package(packet, 0)
        return WAIT_ACK_INFO
    elif type_package == SUBS_NACK:
        tries = -1
        print(f"{time.strftime('%H:%M:%S')}: INFO  => Descartat paquet de subscripció enviat, motiu: {data.decode()}")
        return NOT_SUBSCRIBED
    elif type_package == SUBS_REJ:
        print(f"{time.strftime('%H:%M:%S')}: INFO  => Descartat paquet de subscripció enviat, motiu: {data.decode()}")
        return NOT_SUBSCRIBED


def create_hello():
    data = client_config['Name'] + "," + client_config['Situation']
    hello_pdu = struct.pack('1B13s9s80s', HELLO, client_config['MAC'].encode(), server_data['random'].encode(),
                            data.encode())
    return hello_pdu


def create_subs_req():
    rand_num: str = '0' * 8
    controller_info = client_config['Name'] + "," + client_config['Situation']
    packet = struct.pack('1B13s9s80s', SUBS_REQ, client_config['MAC'].encode(), rand_num.encode(),
                         controller_info.encode())
    return packet


def get_command_name(command):
    if command == SUBS_REQ:
        return "SUBS_REQ"
    elif command == SUBS_ACK:
        return "SUBS_ACK"
    elif command == SUBS_REJ:
        return "SUBS_REJ"
    elif command == SUBS_INFO:
        return "SUBS_INFO"
    elif command == INFO_ACK:
        return "INFO_ACK"
    elif command == SUBS_NACK:
        return "SUBS_NACK"
    elif command == HELLO:
        return "HELLO"
    elif command == HELLO_REJ:
        return "HELLO_REJ"
    elif command == SEND_DATA:
        return "SEND_DATA"
    elif command == SET_DATA:
        return "SEND_DATA"
    elif command == GET_DATA:
        return "GET_DATA"
    elif command == DATA_ACK:
        return "DATA_ACK"
    elif command == DATA_NACK:
        return "DATA_NAK"
    else:
        return "DATA_REJ"


def debug_package(buffer, flag):
    lon_bytes = len(buffer)
    command = get_command_name(buffer[0])
    mac = buffer[1:14].decode()
    random_num = buffer[14:23].decode()
    index = buffer[23:].find(b'\x00')
    value = buffer[23:(24 + index)].decode()
    if flag == 0:
        print(f"{time.strftime('%H:%M:%S')}: DEBUG.  => Enviat: bytes={lon_bytes}, comanda={command}, mac={mac}, "
              f"rndm={random_num}, dades={value}")
    else:
        print(f"{time.strftime('%H:%M:%S')}: DEBUG.  => Rebut: bytes={lon_bytes}, comanda={command}, mac={mac}, "
              f"rndm={random_num}, dades={value}")


def subscribe_process():
    global sock_udp, sock_udp2, next_state, tries, pid, no_response
    o = 3
    u = 2
    r = 2
    v = 2
    s = 3
    no_response = 0
    if debug:
        print(f"{time.strftime('%H:%M:%S')}: DEBUG.  => Inici bucle de servei equip: {client_config['Name']}")
    while True:
        if next_state == DISCONNECTED:
            no_response = 0
            sock_udp.close()
            setup_udp()
            print(f"{time.strftime('%H:%M:%S')}: MSG.  => Controlador en l'estat: DISCONNECTED, procés de "
                  f"subscripció: {tries}")
            subs_req_pdu = create_subs_req()
            sock_udp.sendto(subs_req_pdu, (client_config['Server'], int(client_config['Srv-UDP'])))
            next_state = WAIT_ACK_SUBS
            print(f"{time.strftime('%H:%M:%S')}: MSG.  => Controlador passa a l'estat: WAIT_ACK_SUBS")

        elif next_state == NOT_SUBSCRIBED:
            tries += 1
            if tries > o:
                if debug:
                    print(f"{time.strftime('%H:%M:%S')}: DEBUG => Tancat socket UDP per la comunicació amb el servidor")
                print(f"{time.strftime('%H:%M:%S')}: "
                      f"MSG.  => Superat el nombre de processos de subscripció ({tries - 1})")

                sock_udp.close()
                exit(0)
            print(f"{time.strftime('%H:%M:%S')}: MSG.  => Controlador en l'estat: NOT_SUBSCRIBED, procés de "
                  f"subscripció: {tries}")
            subs_req_pdu = create_subs_req()
            sock_udp.sendto(subs_req_pdu, (client_config['Server'], int(client_config['Srv-UDP'])))
            if debug:
                debug_package(subs_req_pdu, 0)
            next_state = WAIT_ACK_SUBS
            print(f"{time.strftime('%H:%M:%S')}: MSG.  => Controlador passa a l'estat: WAIT_ACK_SUBS")

        elif next_state == WAIT_ACK_SUBS:
            if tries > o:
                if debug:
                    print(f"{time.strftime('%H:%M:%S')}: DEBUG => Tancat socket UDP per la comunicació amb el servidor")
                print(f"{time.strftime('%H:%M:%S')}: "
                      f"MSG.  => Superat el nombre de processos de subscripció ({tries - 1})")

                sock_udp.close()
                exit(0)
            next_state = wait_ack_subs_state()
            if next_state == NOT_SUBSCRIBED:
                print(f"{time.strftime('%H:%M:%S')}: MSG.  => Controlador passa a l'estat: NOT_SUBSCRIBED")
                time.sleep(u)
            elif next_state == WAIT_ACK_INFO:
                print(f"{time.strftime('%H:%M:%S')}: MSG.  => Controlador passa a l'estat: WAIT_ACK_INFO")
                sock_udp.settimeout(None)

        elif next_state == WAIT_ACK_INFO:
            info_ack_pdu, serv = sock_udp2.recvfrom(1500)
            if debug:
                debug_package(info_ack_pdu, 1)
            server_data['TCP-port'] = info_ack_pdu[23:29].decode().strip('\x00')
            if check_server_data(info_ack_pdu, serv):
                next_state = SUBSCRIBED
                if debug:
                    print(f"{time.strftime('%H:%M:%S')}: DEBUG => Acceptada la subscripció del controlador en el "
                          f"servidor")
                print(f"{time.strftime('%H:%M:%S')}: MSG.  => Controlador passa a l'estat: SUBSCRIBED")
            else:
                next_state = NOT_SUBSCRIBED
                print(f"{time.strftime('%H:%M:%S')}: MSG.  => Controlador passa a l'estat: NOT_SUBSCRIBED")

        elif next_state == SUBSCRIBED:
            hello_pdu = create_hello()
            sock_udp.sendto(hello_pdu, (client_config['Server'], int(client_config['Srv-UDP'])))
            if debug:
                debug_package(hello_pdu, 0)
            sock_udp.settimeout(r * v)
            if debug:
                print(f"{time.strftime('%H:%M:%S')}: DEBUG => Establert temporitzador per enviament HELLO")
            try:
                buffer, check_serv = sock_udp.recvfrom(1500)
                if debug:
                    debug_package(buffer, 1)
                if (not check_server_data(buffer, check_serv) or check_serv[0] != server_data['IP']
                        or get_command_name(buffer[0]) == "HELLO_REJ"):
                    if get_command_name(buffer[0]) == "HELLO_REJ" and debug:
                        print(f"{time.strftime('%H:%M:%S')}: DEBUG => Rebut paquet de rebuig de HELLO")
                    next_state = NOT_SUBSCRIBED
            except socket.timeout:
                print(f"{time.strftime('%H:%M:%S')}: MSG. => Finalitzat el temporitzador per "
                      f"la confirmació del primer HELLO (4 seg.)")
                next_state = NOT_SUBSCRIBED
            sock_udp.settimeout(None)

            if next_state == NOT_SUBSCRIBED:
                print(f"{time.strftime('%H:%M:%S')}: MSG.  => Controlador passa a l'estat: NOT_SUBSCRIBED")
            else:
                setup_tcp()
                print(f"{time.strftime('%H:%M:%S')}: MSG.  => Obert port TCP {client_config['Local-TCP']} per la "
                      f"comunicació amb el servidor")
                pid = os.fork()
                if debug:
                    print(f"{time.strftime('%H:%M:%S')}: DEBUG  => Procés creat per enviament de HELLO")
                if pid == 0:
                    read_terminal()
                print(f"{time.strftime('%H:%M:%S')}: MSG.  => Controlador passa a l'estat: SEND_HELLO")
                next_state = SEND_HELLO

        elif next_state == SEND_HELLO:
            flag = send_hello(v)
            if s == no_response or flag == -1:
                os.kill(pid, signal.SIGUSR1)
                next_state = DISCONNECTED
                print(f"{time.strftime('%H:%M:%S')}: MSG.  => Controlador passa a l'estat: DESCONNECTED (Sense "
                      f"resposta a {s} HELLO'S)")


def setup_udp():
    global sock_udp
    sock_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


def parse_arguments():
    global debug
    if len(sys.argv) == 2 and sys.argv[1] == '-d':
        debug = True
        process_config("client.cfg")
    elif len(sys.argv) >= 3 and sys.argv[1] == '-c':
        process_config(sys.argv[2])
        if len(sys.argv) == 4 and sys.argv[3] == '-d':
            debug = True
    else:
        process_config("client.cfg")
    if debug:
        print(f"{time.strftime('%H:%M:%S')}: DEBUG.  => Llegits paràmetres de línia de comandes")


if __name__ == "__main__":
    global sock_udp, sock_tcp, sock_tcp2, sock_udp2
    parse_arguments()
    try:
        signal.signal(signal.SIGINT, sig_int)
        signal.signal(signal.SIGUSR2, sig_usr2)
        signal.signal(signal.SIGUSR1, sig_usr1)
        setup_udp()
        subscribe_process()
        sock_udp.close()
    except Exception as e:
        print("Error:", e)
        sys.exit(-1)
    else:
        print("Error en los arguments")
