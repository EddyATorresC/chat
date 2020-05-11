#!/usr/bin/env python3
"""Script for Tkinter GUI chat client."""
from socket import AF_INET, socket, SOCK_STREAM
import threading
import tkinter
from tkinter import ttk, filedialog, messagebox
import select
import os
import traceback
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import Poly1305
from Crypto.PublicKey import RSA
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


class Checkbox(tkinter.Checkbutton):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.variable = None

    def set_myvar(self, mv):
        self.variable = mv

    def checked(self):
        return self.variable.get()

    # def check(self):
    #     self.variable.set(True)
    #
    # def uncheck(self):
    #     self.variable.set(False)


def sendName(event=None):  # event is passed by binders.
    """Handles sending of messages."""
    name = my_string.get()
    if name.find('\n') > 0 or len(name) == 0:
        msg_label.configure(text='Invalid characters in user name')
        return
    client_socket.sendall(get_message(name).encode('ASCII'))
    print(name)
    ready = select.select([client_socket], [], [])
    if ready[0]:
        msg = client_socket.recv(BUFSIZ).decode('ASCII')
        msg = parse_message(msg)
        print(msg)
        # msg_list.insert(tkinter.END, msg)
        # msg_label.pack_forget()
        msg_label.configure(text=msg)
        # msg_label.pack()
        if msg == name:
            # print('closed?')
            error_string.set("OK")
            top.destroy()


def on_closing(event=None):
    """This function is to be called when the window is closed."""
    top.quit()


def on_close_list(event=None):
    del_path = prefix + 'private.pem'
    delete_file(del_path)
    del_path = prefix + 'public.pem'
    delete_file(del_path)
    client_socket.close()
    print('Socket closed')
    # refresh_button.destroy()
    r_loop.join()
    # children = top.children
    # for child in children:
    #
    top.quit()
    # raise ValueError


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
    my_msg = decrypt_message(private_key, encrypted_message)
    return get_message(my_msg)


def getCheckedItems(container):
    children = container.children
    values = []
    for fkey in children:
        frame = children[fkey].children
        cb = frame[list(frame.keys())[0]]
        value = cb.checked()
        if value:
            cb.deselect()
            values.append(value)
    return values


def request_room(container):
    try:
        members_list = getCheckedItems(container)
        while True:
            ready = select.select([client_socket], [client_socket], [])
            if not ready[0] and ready[1]:
                write_lock.acquire()
                client_socket.sendall(encrypt_message(server_key, '/*-*/create_room/*+*/'))
                break
        send_list = True
        while send_list:
            ready = select.select([client_socket], [], [], 1)
            if not ready[0]:
                client_socket.sendall(encrypt_message(server_key, '\n'.join(members_list)))
                send_list = False
        write_lock.release()
    except Exception as ex:
        print(ex)


def accept_request(msg):
    room_port = msg
    room_port = room_port.replace('/*-*/c_k/*+*/', '')
    room_port = int(room_port)
    print(room_port)
    room_socket = socket(AF_INET, SOCK_STREAM)
    room_socket.connect((HOST, room_port))
    room_socket.sendall(client_id.encode('ASCII'))
    # print('connection made')
    member_info = {}
    received_msg = room_socket.recv(BUFSIZ)
    # print('got codified list')
    # print(received_msg)
    list_string = (decrypt_message(private_key, received_msg))
    list_string = list_string.split('\n')
    # print(list_string)
    for member in list_string:
        ready = select.select([room_socket], [], [])
        if ready[0]:
            member_key = room_socket.recv(BUFSIZ)
            member_key = member_key.decode('ASCII')
            member_info[member] = RSA.import_key(member_key)
        # print('Key received')
    chat_window(room_socket, member_info)


def list_manager(client_socket, server_key, private_key, list_container):
    ready = select.select([client_socket], [client_socket], [])
    if not ready[0] and ready[1]:
        client_socket.sendall(encrypt_message(server_key, '/*-*/ref_list/*+*/'))
    ready = select.select([client_socket], [], [], 1)
    if ready[0]:
        list_string = (decrypt_message(private_key, client_socket.recv(BUFSIZ)))
        if "/*-*/c_k/*+*/" in list_string:
            print('Room request received')
            print(list_string)
            accept_request(list_string)
            ready = select.select([client_socket], [], [], 5)
            if ready[0]:
                list_string = (decrypt_message(private_key, client_socket.recv(BUFSIZ)))
            else:
                return
        list_shower(list_container, list_string)


def chat_window(room_socket, member_info):
    window = tkinter.Toplevel(top)
    window.title(client_id + " chat")
    w = 500
    h = 200
    window.geometry("%dx%d+%d+%d" % (w, h, screen_w / 2 - w / 2, screen_h / 2 - h / 2))
    chat_text_frame = tkinter.Frame(window)
    chat_scrollbar = tkinter.Scrollbar(chat_text_frame)  # To navigate through past messages.
    # Following will contain the messages.
    text_list = tkinter.Listbox(chat_text_frame, yscrollcommand=chat_scrollbar.set)  # append on receive
    text_list.insert(tkinter.END, 'Hello! Welcome to the chat. Members:')
    text_list.insert(tkinter.END, ' ,'.join(list(member_info.keys())))
    chat_scrollbar.pack(side=tkinter.RIGHT, fill=tkinter.Y)
    text_list.pack(side=tkinter.LEFT, fill=tkinter.BOTH, expand=True)

    my_text = tkinter.StringVar()  # For the messages to be sent.
    my_text.set("")
    chat_text_frame.pack(fill=tkinter.BOTH, side=tkinter.TOP, expand=True)
    interact_frame = tkinter.Frame(window)
    chat_field = tkinter.Entry(interact_frame, textvariable=my_text)
    chat_field.bind("<Return>", lambda event=None: chat_send(room_socket, my_text, member_info, text_list))
    chat_field.pack(fill=tkinter.X, side=tkinter.LEFT, expand=True)

    file_btn = tkinter.Button(interact_frame, text='File',
                              command=lambda event=None: send_file(window, client_socket, room_socket, member_info,
                                                                   text_list))
    file_btn.pack(side=tkinter.RIGHT, expand=False)
    interact_frame.pack(fill=tkinter.X, side=tkinter.BOTTOM)

    recv_t = threading.Thread(target=chat_recv, args=(room_socket, text_list, member_info, window))
    recv_t.start()
    window.protocol("WM_DELETE_WINDOW", lambda event=None: on_closed_room(window, room_socket, recv_t, event))


def on_closed_room(window, s, t, event=None):
    s.close()
    t.join()
    window.destroy()


def chat_send(room_socket, my_text, member_info, text_list):
    m = my_text.get()
    if len(m) == 0:
        return
    # mac = Poly1305.new(key=key, cipher=AES, nonce=nonce)
    for member in member_info:
        destination = member.encode('ASCII')
        to_msg = encrypt_message(member_info[member], client_id + ": " + m)
        mac = Poly1305.new(key=key, cipher=AES, nonce=nonce)
        mac.update(to_msg)
        mac_hex_digest = mac.hexdigest().encode('ASCII')  # mac
        ready = select.select([room_socket], [room_socket], [])
        if not ready[0] and ready[1]:
            room_socket.sendall(destination)
        ready = select.select([room_socket], [room_socket], [])
        if not ready[0] and ready[1]:
            room_socket.sendall(to_msg)
        #     inicio mac
        ready = select.select([room_socket], [room_socket], [])
        if not ready[0] and ready[1]:
            room_socket.sendall(mac_hex_digest)
        #         final mac
    text_list.insert(tkinter.END, client_id + ": " + m)
    # # Instead of just writing to the list, recv the msg as confirmation
    # destination = encrypt_message(server_key, client_id)
    # to_msg = encrypt_message(public_key, client_id + ": " + m)
    # ready = select.select([room_socket], [room_socket], [])
    # if not ready[0] and ready[1]:
    #     room_socket.sendall(destination)
    # ready = select.select([room_socket], [room_socket], [])
    # if not ready[0] and ready[1]:
    #     room_socket.sendall(to_msg)
    my_text.set("")


def chat_recv(room_socket, text_list, member_info, w):
    while len(member_info) > 0:
        try:
            if not w.winfo_exists():
                break
            ready = select.select([room_socket], [], [], 1)
            if ready[0]:
                enc_msg = room_socket.recv(BUFSIZ)
                if len(enc_msg) == 0:
                    raise ConnectionError
                # inicio mac
                ready = select.select([room_socket], [], [])
                if ready[0]:
                    mac_hex_digest = room_socket.recv(BUFSIZ).decode('ASCII')
                #     final mac
                recv_msg = (decrypt_message(private_key, enc_msg))
                if "/*-*/s_l/*+*/" in recv_msg:
                    m_name = recv_msg.replace("/*-*/s_l/*+*/", "")
                    del member_info[m_name]
                    text_list.insert(tkinter.END,m_name+' left the room')
                    continue
                if "/*file-sent*/" in recv_msg:
                    f_name = recv_msg.replace("/*file-sent*/", "", 1)
                    text_list.insert(tkinter.END, f_name)
                    f_name = f_name[f_name.find(" |") + 2:len(f_name)]
                    get_file(w, client_socket, f_name)
                    continue
                mac_verify = Poly1305.new(key=key, nonce=nonce, cipher=AES, data=enc_msg)
                mac_verify.hexverify(mac_hex_digest)
                text_list.insert(tkinter.END, recv_msg)
        except ConnectionError:
            # traceback.print_exc()
            print("Closed from server?")
            break
        except OSError:
            # traceback.print_exc()
            print("Closed from client")
            break
        except RuntimeError:
            print("App ended, closing all windows")
            break
        except ValueError:
            text_list.insert(tkinter.END, "2-end Authentication FAILED! Closing connection")
            traceback.print_exc()
            print("MAC check failed")
            break
        except:
            traceback.print_exc()
    if len(member_info) == 0:
        text_list.insert(tkinter.END, 'Everyone else left the chat room. Closing chat room')
    room_socket.close()


def get_file(par, server_socket, fname):
    if messagebox.askyesno("File received", "Download " + fname + "?"):
        try:
            write_lock.acquire()
            ready = select.select([server_socket], [server_socket], [])
            if not ready[0] and ready[1]:
                server_socket.sendall(encrypt_message(server_key, "/*-*/get_file/*+*/" + fname))
                ready = select.select([server_socket], [], [])
                if ready[0]:
                    get_port = server_socket.recv(BUFSIZ)
                    write_lock.release()
                    if len(get_port) > 0:
                        get_port = decrypt_message(private_key, get_port)
                        get_port = get_port.replace("/*-*/p_num/*+*/", "")
                        get_port = int(get_port)
                        get_socket = socket(AF_INET, SOCK_STREAM)
                        get_socket.connect((HOST, get_port))
                        get_thread = threading.Thread(target=do_getfile, args=(par, fname, get_socket))
                        get_thread.start()
                    pass
        except:
            traceback.print_exc()


def on_close_fileget(s, wind):
    s.close()
    wind.destroy()


def do_getfile(par, fname, g):
    try:
        f_size = g.recv(BUFSIZ)
        f_size = decrypt_message(private_key, f_size)
        f_size = f_size.replace("/*-EXISTS-*/", "", 1)
        f_size = int(f_size)
        f_info = os.path.splitext(fname)
        new_file = filedialog.asksaveasfile(mode="wb", parent=par, defaultextension=f_info[1], initialfile=f_info[0],
                                            confirmoverwrite=True)
        while not new_file.writable():
            new_file = filedialog.asksaveasfile(mode="wb", parent=par, defaultextension=f_info[1],
                                                initialfile=f_info[0],
                                                confirmoverwrite=True)
        progress_wind = tkinter.Toplevel(par)
        progress_wind.title(client_id + " download")
        w = 400
        h = 100
        progress_wind.geometry("%dx%d+%d+%d" % (w, h, screen_w / 2 - w / 2, screen_h / 2 - h / 2))
        progress_frame = tkinter.Frame(progress_wind)
        p_label = tkinter.Label(progress_frame, text=("Downloading file: " + fname))
        p_label.pack()
        p_bar = tkinter.ttk.Progressbar(progress_frame, orient=tkinter.HORIZONTAL, length=100, mode='determinate')
        p_bar.pack()
        progress_frame.pack()
        progress_wind.protocol("WM_DELETE_WINDOW", lambda event=None: on_close_fileget(g, progress_wind))
        totalRecv = 0
        # raise ValueError
        while totalRecv < f_size:
            data = g.recv(BUFSIZ)
            totalRecv += len(data)
            new_file.write(data)
            p_bar['value'] = (float(totalRecv) / float(f_size) * 100)

        ready = select.select([g], [], [], 2)
        if ready[0]:
            confirmation = g.recv(BUFSIZ)
            if decrypt_message(private_key, confirmation) != 'DONE':
                p_label.configure(text='An error ocurred.')
                raise Exception
            else:
                p_label.configure(text='File downloaded!')
        else:
            p_label.configure(text='An error ocurred. No response from server')
            raise Exception
        new_file.close()
    except:
        print(len(confirmation))
        traceback.print_exc()
    finally:
        g.close()
        new_file.close()


def send_file(par, server_socket, room_socket, member_info, text_list):
    rep = filedialog.askopenfilename(
        parent=par,
        initialdir='./c_files',
        initialfile='',
        filetypes=[
            ("PNG", "*.png"),
            ("JPEG", "*.jpg"),
            ("All files", "*")],
        multiple=False)
    if rep != '':
        f_name = os.path.split(rep)[1]
        try:
            write_lock.acquire()
            ready = select.select([server_socket], [server_socket], [])
            if not ready[0] and ready[1]:
                file_size = os.path.getsize(rep)
                server_socket.sendall(
                    encrypt_message(server_key, "/*-*/send_file/*+*/" + f_name + "/*-*/" + str(file_size)))
                ready = select.select([server_socket], [], [])
                if ready[0]:
                    send_port = server_socket.recv(BUFSIZ)
                    write_lock.release()
                    if len(send_port) > 0:
                        send_port = decrypt_message(private_key, send_port)
                        send_port = send_port.replace("/*-*/p_num/*+*/", "")
                        send_port = int(send_port)
                        send_socket = socket(AF_INET, SOCK_STREAM)
                        send_socket.connect((HOST, send_port))
                        send_thread = threading.Thread(target=do_sendfile,
                                                       args=(send_socket, rep, par, f_name, file_size, room_socket,
                                                             member_info, text_list))
                        send_thread.start()
        except:
            traceback.print_exc()


def on_closing_filesender(wind, s, room_socket, member_info, text_list, fname):
    s.close()
    wind.destroy()
    try:
        for member in member_info:
            destination = member.encode('ASCII')
            to_msg = encrypt_message(member_info[member], "/*file-sent*/" + client_id + " sent a file: |" + fname)
            mac = Poly1305.new(key=key, cipher=AES, nonce=nonce)
            mac.update(to_msg)
            mac_hex_digest = mac.hexdigest().encode('ASCII')  # mac
            ready = select.select([room_socket], [room_socket], [])
            if not ready[0] and ready[1]:
                room_socket.sendall(destination)
            ready = select.select([room_socket], [room_socket], [])
            if not ready[0] and ready[1]:
                room_socket.sendall(to_msg)
            ready = select.select([room_socket], [room_socket], [])
            if not ready[0] and ready[1]:
                room_socket.sendall(mac_hex_digest)
        text_list.insert(tkinter.END, "You sent a file: |" + fname)
    except:
        traceback.print_exc()


def do_sendfile(send_socket, path, par, fname, fsize, room_socket,
                member_info, text_list):
    try:
        progress_wind = tkinter.Toplevel(par)
        progress_wind.title(client_id + " upload")
        w = 400
        h = 100
        progress_wind.geometry("%dx%d+%d+%d" % (w, h, screen_w / 2 - w / 2, screen_h / 2 - h / 2))
        progress_frame = tkinter.Frame(progress_wind)
        p_label = tkinter.Label(progress_frame, text=("Sending file: " + fname))
        p_label.pack()
        p_bar = tkinter.ttk.Progressbar(progress_frame, orient=tkinter.HORIZONTAL,
                                        length=100, mode='determinate')
        p_bar.pack()
        progress_frame.pack()
        progress_wind.protocol("WM_DELETE_WINDOW",
                               lambda event=None: on_closing_filesender(progress_wind, send_socket, room_socket,
                                                                        member_info, text_list, fname))
        with open(path, 'rb') as f:
            bytesToSend = f.read(BUFSIZ)
            send_socket.send(bytesToSend)
            totalSent = len(bytesToSend)
            while totalSent < fsize:
                try:
                    ready = select.select([], [send_socket], [], 1)
                    if not ready[1]:
                        continue
                    bytesToSend = f.read(BUFSIZ)
                    totalSent += len(bytesToSend)
                    send_socket.send(bytesToSend)
                    # p_label.configure(text=str(totalSent)+" of " + str(fsize))
                    # print("{0:.2f}".format((float(totalSent) / float(file_size)) * 100) + "% Done")
                    p_bar['value'] = (float(totalSent) / float(fsize) * 100)
                except:
                    print(str(totalSent) + " of " + str(fsize))
                    traceback.print_exc()
                    break
        # p_label.configure(text='File sent!')
        ready = select.select([send_socket], [], [], 2)
        if ready[0]:
            confirmation = send_socket.recv(BUFSIZ)
            if decrypt_message(private_key, confirmation) != 'DONE':
                p_label.configure(text='An error ocurred.')
                raise Exception
            else:
                p_label.configure(text='File sent!')
                # progress_wind.destroy()
        else:
            p_label.configure(text='An error ocurred. No response from server')
            raise Exception
    except:
        traceback.print_exc()
    finally:
        send_socket.close()


def list_shower(container, member_list):
    choices = member_list.split('\n')
    children = container.children.copy()
    for childkey in children:
        child = children[childkey]
        if child.winfo_exists():
            this_choice = child.children.copy()
            this_choice = this_choice[list(this_choice.keys())[0]].checked()
            if this_choice in choices:
                choices.remove(this_choice)
                continue
            child.pack_forget()
            child.destroy()

    for choice in choices:
        if choice == client_id:
            continue
        f = tkinter.Frame(container)
        f.configure(background="dark gray")
        var = tkinter.StringVar(value=choice)
        cb = Checkbox(f, var=var, text=choice,
                      onvalue=choice, width=int(wind_w - 4), offvalue="",
                      anchor="w", background="light gray",
                      relief="flat", highlightthickness=1
                      )
        cb.set_myvar(var)

        bt = tkinter.Button(f, text='>')
        bt.bind('<Button-1>', single_request)
        bt.pack(side=tkinter.RIGHT, ipady=2)
        cb.pack(side=tkinter.TOP, fill=tkinter.X, anchor=tkinter.W, expand=True, padx=2)
        cb.deselect()
        f.pack(side=tkinter.TOP, fill=tkinter.BOTH, anchor=tkinter.W, expand=True, padx=5, pady=5)

    container.pack()


def single_request(event):
    btn = event.widget
    # btn.config(relief=tkinter.SUNKEN)
    # btn['state'] = tkinter.DISABLED
    getCheckedItems(list_container)
    parent_frame = btn.master
    checkbox = parent_frame.children
    checkbox = checkbox[list(checkbox.keys())[0]]
    checkbox.invoke()
    create_button.invoke()
    checkbox.deselect()
    # time.sleep(0.1)
    # btn.config(relief=tkinter.RAISED)
    # btn['state'] = tkinter.NORMAL
    pass


def refresher(client_socket, server_key, private_key, list_container, w_lock):
    while True:
        try:
            select.select([client_socket], [], [], 2)
            if not w_lock.acquire(False):
                continue
            list_manager(client_socket, server_key, private_key, list_container)
            write_lock.release()
        except (ConnectionError, OSError, ConnectionAbortedError, ValueError):
            print('Refresher closed')
            traceback.print_exc()
            break
        except:
            traceback.print_exc()


if __name__ == "__main__":

    top = tkinter.Tk()
    top.title("Chatter Login")
    top.configure(background='gray')
    i_frame = tkinter.Frame(top)
    i_frame.configure(background='gray')
    screen_w = top.winfo_screenwidth()
    screen_h = top.winfo_screenheight()
    wind_w = 500
    wind_h = 120
    top.geometry("%dx%d+%d+%d" % (wind_w, wind_h, screen_w / 2 - wind_w / 2, screen_h / 2 - wind_h / 2))
    error_string = tkinter.StringVar()
    error_string.set("no_name")
    my_string = tkinter.StringVar()  # For the messages to be sent.
    my_string.set("Type a username")
    msg_label = tkinter.Label(i_frame, text="To start, please enter your username", background='gray')
    msg_label.pack(side=tkinter.TOP, pady=5)
    entry_field = tkinter.Entry(i_frame, textvariable=my_string, width=50)
    entry_field.bind("<Return>", sendName)
    entry_field.bind("<ButtonPress>", lambda event=None: my_string.set(""))

    send_button = tkinter.Button(i_frame, text="Send", command=sendName, width=10)
    send_button.pack(side=tkinter.BOTTOM, pady=5)
    entry_field.pack(anchor=tkinter.CENTER, pady=5)
    top.protocol("WM_DELETE_WINDOW", on_closing)
    i_frame.pack(anchor=tkinter.CENTER, fill=tkinter.BOTH, pady=int(0.1 * wind_h))

    HOST = 'localhost'
    PORT = 8888
    BUFSIZ = 2048
    ADDR = (HOST, PORT)

    key = b'The key size has to be 32 bytes!'
    nonce = b'16 byte of nonce'

    try:
        client_socket = socket(AF_INET, SOCK_STREAM)
        client_socket.connect(ADDR)

        top.mainloop()  # Starts GUI execution.

        if error_string.get() != 'OK':
            raise ValueError
        client_socket.sendall(get_message('OK').encode('ASCII'))
        client_id = my_string.get()

        prefix = './c_keys/' + client_id + '_'
        getKeys(prefix)
        private_key = loadPrivateKey(prefix + 'private.pem')
        public_key = loadPublicKey(prefix + 'public.pem')
        print('Keys generated')
        server_key = RSA.import_key(client_socket.recv(BUFSIZ).decode('ASCII'))
        client_socket.sendall(open(prefix + 'public.pem').read().encode('ASCII'))

        # Keys and username sent. Starting list of members app.
        write_lock = threading.Lock()
        top = tkinter.Tk()
        top.title(client_id)
        top.configure(background='gray20')
        top.protocol("WM_DELETE_WINDOW", on_close_list)
        list_container = tkinter.Frame(top)
        list_container.configure(background='gray20')
        wind_w = 0.2 * screen_w
        wind_h = 0.8 * screen_h
        top.geometry("%dx%d+%d+%d" % (wind_w, wind_h, 20, screen_h / 2 - wind_h / 2))
        refresh_button = tkinter.Button(top, text="Reload",
                                        command=lambda: list_manager(client_socket, server_key, private_key,
                                                                     list_container))
        refresh_button.pack()
        create_button = tkinter.Button(top, text="Create Room", command=lambda: request_room(list_container))
        create_button.pack(side=tkinter.BOTTOM)

        r_loop = threading.Thread(target=refresher, args=(client_socket, server_key, private_key,
                                                          list_container, write_lock))
        # top.after(100, lambda: r_loop.start())
        r_loop.start()
        tkinter.mainloop()
        client_socket.close()
        raise ValueError
    except ValueError:
        client_socket.close()
        try:
            on_close_list()
        except:
            pass
