#!/usr/bin/env python3
"""Server for multithreaded (asynchronous) chat application."""
import traceback
import threading
import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import select
import os
import time


def delete_file(path):
    os.remove(os.getcwd() + "/" + path)


def getKeys(path):
    keyPair = RSA.generate(BUFSIZ)

    pubKey = keyPair.publickey()
    # print(f"Public key:  (n={hex(pubKey.n)}, e={hex(pubKey.e)})")
    pubKeyPEM = pubKey.exportKey()
    # print(pubKeyPEM.decode('ascii'))

    # print(f"Private key: (n={hex(pubKey.n)}, d={hex(keyPair.d)})")
    privKeyPEM = keyPair.exportKey()
    # print(privKeyPEM.decode('ascii'))

    file_out = open(path + "private.pem", "wb")
    file_out.write(privKeyPEM)

    file_out = open(path + "public.pem", "wb")
    file_out.write(pubKeyPEM)


def loadPrivateKey(path):
    private_key = RSA.import_key(open(path).read())
    return private_key


def loadPublicKey(path):
    receiver_key = RSA.import_key(open(path).read())
    return receiver_key


def encrypt_message(public_key, unencrypted_message):
    encryptor = PKCS1_OAEP.new(public_key)
    encrypted = encryptor.encrypt(unencrypted_message.encode('ASCII'))
    return encrypted


def decrypt_message(private_key, encrypted_message):
    decryptor = PKCS1_OAEP.new(private_key)
    decrypted = decryptor.decrypt(encrypted_message)
    return decrypted.decode('ASCII')


def get_list():
    server_list = '\n'.join(clients.keys())
    return server_list


def parse_message(message):
    message = message.strip('\0')
    message = message[4:]
    return message


def get_message(message):
    return str(len(message) + 1).zfill(4) + message + '\0'


def get_encmessage(public_key, unencrypted_message):
    my_msg = encrypt_message(public_key, unencrypted_message)
    return get_message(my_msg)


def parse_encmessage(private_key, encrypted_message):
    my_msg = decrypt_message(private_key, parse_message(encrypted_message))
    return my_msg


def client_requests(request):
    if '/*-*/ref_list/*+*/' in request:
        return 'refresh'
    if '/*-*/create_room/*+*/' in request:
        return 'room'
    if "/*-*/send_file/*+*/" in request:
        return 'file_up'
    if "/*-*/get_file/*+*/" in request:
        return 'file_down'
    return None


def deal_with_client(conn, addr):
    """Handles a single client connection."""
    try:
        client_id = None
        while client_id is None:
            ready = select.select([conn], [], [], 5)
            if ready[0]:
                msg = conn.recv(BUFSIZ)
                msg = parse_message(msg.decode('ASCII'))
                if msg in clients.keys():
                    conn.sendall(get_message('Username already in use. Please use another').encode('ASCII'))
                else:
                    client_id = msg

        conn.sendall(get_message(client_id).encode('ASCII'))
        prefix = './s_keys/' + client_id + '_'
        getKeys(prefix)
        private_key = loadPrivateKey(prefix + 'private.pem')
        public_key = loadPublicKey(prefix + 'public.pem')
        ready = select.select([conn], [], [])
        if ready[0]:
            conn.recv(BUFSIZ)
        conn.sendall(open(prefix + 'public.pem').read().encode('ASCII'))
        client_key = None
        while client_key is None:
            ready = select.select([conn], [], [], 10)
            if ready[0]:
                msg = conn.recv(BUFSIZ)
                client_key = msg
        client_key_file = client_key.decode('ASCII')
        client_key = RSA.import_key(client_key_file)
        room_request = None
        clients[client_id] = [addr, conn, room_request, client_key_file]

        while True:
            my_data = clients.get(client_id)
            my_requests = my_data[2]
            if my_requests is not None:
                ready = select.select([], [conn], [], 10)
                if ready[1]:
                    conn.sendall(encrypt_message(client_key, "/*-*/c_k/*+*/" + str(my_requests)))
                    my_data[2] = None
                    clients[client_id] = my_data
                    continue

            ready = select.select([conn], [], [], 5)
            if ready[0]:
                msg = conn.recv(BUFSIZ)
                if len(msg) == 0:
                    conn.close()
                    continue
                msg = decrypt_message(private_key, msg)
                action = client_requests(msg)

                if action is None:
                    conn.sendall(encrypt_message(client_key, "Error on communication"))
                    continue

                if action == 'refresh':
                    conn.sendall(encrypt_message(client_key, get_list()))
                    continue
                if action == 'room':
                    ready = select.select([conn], [], [], 5)
                    if ready[0]:
                        msg = conn.recv(BUFSIZ)
                        msg = decrypt_message(private_key, msg)
                        m_list = msg.split('\n')

                        target_data = clients.get(m_list[0], 'error')
                        if target_data == 'error':
                            conn.sendall(encrypt_message(client_key, 'ID not found'))
                            continue
                        manage_room(m_list, client_id, private_key)
                        continue
                if action == 'file_up':
                    f_info = msg.replace("/*-*/send_file/*+*/", "")
                    f_info = f_info.split("/*-*/")
                    get_socket = socket_request()
                    get_thread = threading.Thread(target=save_file, args=(f_info, get_socket, client_key))
                    get_thread.start()
                    conn.sendall(encrypt_message(client_key, "/*-*/p_num/*+*/" + str(get_socket.getsockname()[1])))
                    continue

                if action == 'file_down':
                    f_name = msg.replace("/*-*/get_file/*+*/", "")
                    send_socket = socket_request()
                    send_thread = threading.Thread(target=send_file, args=(f_name, send_socket, client_key))
                    send_thread.start()
                    conn.sendall(encrypt_message(client_key, "/*-*/p_num/*+*/" + str(send_socket.getsockname()[1])))
                    continue

    except (ConnectionError, ValueError):
        try:
            del clients[client_id]
            print(client_id + " has left the app")
            del_path = prefix + 'private.pem'
            delete_file(del_path)
            del_path = prefix + 'public.pem'
            delete_file(del_path)
        except NameError:
            pass
        except KeyError:
            print("Connection closed with anonymous client")
            pass
    except Exception as ex:
        traceback.print_exc()


def save_file(f_info, s, ck):
    try:
        s.listen(1)
        f_socket, _ = s.accept()
        f = open('./s_files/upload_' + f_info[0], 'wb')
        totalRecv = 0
        while totalRecv < int(f_info[1]):
            data = f_socket.recv(BUFSIZ)
            totalRecv += len(data)
            f.write(data)
        f_socket.sendall(encrypt_message(ck, 'DONE'))
        time.sleep(1)
    except:
        traceback.print_exc()
    finally:
        f.close()
        s.close()


def send_file(f_name, s, ck):
    try:
        s.listen(1)
        f_socket, _ = s.accept()
        path = './s_files/upload_' + f_name
        f = open(path, 'rb')
        f_size = os.path.getsize(path)
        f_socket.sendall(encrypt_message(ck, "/*-EXISTS-*/" + str(f_size)))
        totalSent = 0
        while totalSent < f_size:
            ready = select.select([], [f_socket], [], 1)
            if not ready[1]:
                continue
            bytesToSend = f.read(BUFSIZ)
            f_socket.send(bytesToSend)
            totalSent += len(bytesToSend)
        f_socket.sendall(encrypt_message(ck, 'DONE'))
        time.sleep(1)
    except:
        traceback.print_exc()
    finally:
        f.close()
        s.close()


def socket_request():
    new_member_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        new_member_socket.bind((HOST, 0))
        return new_member_socket
    except:
        traceback.print_exc()
        return None


def manage_room(m_list, sender, priv):
    s_request = socket_request()
    new_port = s_request.getsockname()[1]

    n = threading.Thread(target=room_maker, args=(s_request, m_list + [sender], priv))
    n.start()
    sender_data = clients.get(sender)
    sender_data[2] = new_port
    clients[sender] = sender_data
    for member in m_list:
        member_data = clients.get(member)
        member_data[2] = new_port
    #         clients[member] = member_data
    try:
        raise ValueError
    except:
        print(m_list + [sender])


def room_maker(room_socket, member_list, priv):
    members_data = {}
    room_socket.listen(len(member_list))
    for _ in member_list:
        try:
            member_socket, member_address = room_socket.accept()
            member = None
            while member is None:
                ready = select.select([member_socket], [], [])
                if ready[0]:
                    member = member_socket.recv(BUFSIZ).decode('ASCII')
            member_key = clients.get(member)[3]

            members_data[member] = [member_socket, member_key, threading.Lock()]
        except ConnectionError:
            # Add cuando todos se desconectan cerrar
            print("Someone left a room. No connection with that user is set.")
        except:
            traceback.print_exc()
            continue
    exchanged = False
    try:
        exchange_keys(members_data)
        exchanged = True
    except:
        traceback.print_exc()

    while exchanged and len(members_data) > 1:
        try:
            res = [members_data.get(sub)[0] for sub in list(members_data.keys())]
            ready = select.select(res, [], [], 5)
            if ready[0]:
                for writer in ready[0]:
                    for _ in range(len(member_list) - 1):
                        errorconn = writer
                        msg = writer.recv(BUFSIZ)
                        if len(msg) == 0:
                            raise ConnectionError
                        destination = msg.decode('ASCII')
                        ready = select.select([writer], [], [])
                        if ready[0]:
                            enc_msg = writer.recv(BUFSIZ)
                            # mac inicio
                            ready = select.select([writer], [], [])
                            if ready[0]:
                                tag = writer.recv(BUFSIZ)
                            # mac final
                            if len(enc_msg) == 0:
                                raise ConnectionError
                            broadcast(members_data, [destination], [enc_msg, tag])

        except (ConnectionError, ConnectionResetError):
            print("Someone left a room. Removing that user from list.")
            errorconn.close()
            for member in members_data:
                if errorconn in members_data[member]:
                    del members_data[member]
                    member_list.remove(member)
                    print(member + " left the room")
                    # broadcast(members_data, member_list, (member + " left the room").encode('ASCII'))
                    for m_remaining in members_data:
                        rem = members_data[m_remaining]
                        # print(rem)
                        # bye_msg = encrypt_message(RSA.import_key(rem[1]), (member + " left the room"))
                        remc = rem[0]
                        # ready = select.select([remc], [remc], [])
                        # if not ready[0] and ready[1]:
                        #     broadcast(members_data, [m_remaining], [bye_msg])
                        bye_msg = encrypt_message(RSA.import_key(rem[1]), ("/*-*/s_l/*+*/" + member))
                        ready = select.select([remc], [remc], [])
                        if not ready[0] and ready[1]:
                            broadcast(members_data, [m_remaining], [bye_msg])
                    break
            # traceback.print_exc()
        except:
            traceback.print_exc()
            continue
    try:
        room_socket.close()
        raise Exception
    except:
        del members_data
        print("Room closed")


def exchange_keys(member_info):
    for member in list(member_info.keys()):
        try:
            t_list = list(member_info.keys()).copy()
            t_list.remove(member)
            m_k = member_info.get(member)[1]
            m_s = member_info.get(member)[0]
            m_l = member_info.get(member)[2]
            m_k = RSA.import_key(m_k)

            # doBroadcast(m_s, encrypt_message(m_k, '\n'.join(t_list)), m_l)
            # for m_n in t_list:
            #     doBroadcast(m_s, (member_info.get(m_n)[1]).encode('ASCII'), m_l)

            # mac
            to_send = [encrypt_message(m_k, '\n'.join(t_list))]
            doBroadcast(m_s, to_send, m_l)
            to_send = []
            for m_n in t_list:
                to_send.append((member_info.get(m_n)[1]).encode('ASCII'))
            doBroadcast(m_s, to_send, m_l)
            #     mac end
        except:
            traceback.print_exc()


def broadcast(member_info, to_list, to_send):
    for s in to_list:
        m_s = member_info.get(s)[0]
        m_l = member_info.get(s)[2]
        ts = threading.Thread(target=doBroadcast, args=(m_s, to_send, m_l))
        ts.start()


def doBroadcast(m_s, to_send, lock):
    try:
        while True:
            ready = select.select([m_s], [], [], 1)
            if lock.acquire(False) and not ready[0]:
                for msg in to_send:
                    while ready[0] and not ready[1]:
                        ready = select.select([m_s], [m_s], [])
                    m_s.sendall(msg)

                lock.release()
                # raise ValueError
                break
    except:
        print(msg)
        traceback.print_exc()


HOST = 'localhost'
PORT = 8888
BUFSIZ = 2048
ADDR = (HOST, PORT)

if __name__ == "__main__":
    bind_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bind_socket.bind(ADDR)
    bind_socket.listen(1)
    ADDR = None

    clients = {}
    ports = {}
    print("Server listening at port: " + str(PORT))

    while True:
        try:
            new_socket, from_address = bind_socket.accept()
            t = threading.Thread(target=deal_with_client, args=(new_socket, from_address))
            t.start()
            print('Dealing with client: ' + str(from_address))
        except KeyboardInterrupt:
            print('Program closing...')
            break

    bind_socket.close()
