import os
import rsa
from rsa.transform import int2bytes, bytes2int
import time
import json
import base64
import shutil
import qrcode
import bcrypt
import random
import yadisk
import keyring
import smtplib
import requests
import psycopg2
import threading
import tkinter as tk
from tkinter import *
from PIL import Image
from datetime import datetime, timezone
from tkinter import messagebox
from tkinter import filedialog
from keyring.backends.Windows import WinVaultKeyring

# from keyring.backends.OS_X import Keyring

keyring.set_keyring(WinVaultKeyring())
y = yadisk.YaDisk(token="AgAAAABITC7sAAbGEG8sF3E00UCxjTQXUS5Vu28")
backend_url = "http://chat-b4ckend.herokuapp.com/"

code = None
chats = {}
pin_chats = []
current_chat = "-1"
root = tk.Tk()
spacing, spacing_2 = 0, 0
w = root.winfo_screenwidth() // 2 - 140
h = root.winfo_screenheight() // 2 - 100
user_id, email, user_login, user_password = '', '', '', ''
var = IntVar()
private_key = rsa.PrivateKey(1, 2, 3, 4, 5)
files_dir = 'files'
time_to_check = 60.0
dt = datetime.now(timezone.utc).astimezone()
utc_diff = dt.utcoffset()

try:
    os.mkdir(files_dir)
except FileExistsError:
    pass


def exception_handler(e, connect=None, cursor=None):
    try:
        if cursor is not None:
            cursor.close()
        if connect is not None:
            connect.close()
        print(e)
    except Exception as e:
        print(e)


def pg_connect():
    try:
        con = psycopg2.connect(
            host="ec2-54-247-107-109.eu-west-1.compute.amazonaws.com",
            database="de81d5uf5eagcd",
            user="guoucmhwdhynrf",
            port="5432",
            password="7720bda9eb76c990aee593f9064fa653136e3a047f989f53856b37549549ebe6")
        cur = con.cursor()
        return con, cur
    except Exception as e:
        print(e)


def auto_check_message():
    try:
        get_message()
    except Exception as e:
        print(e)


def debug(cursor):
    cursor.execute("SELECT * FROM users")
    print(cursor.fetchall())
    cursor.execute("SELECT * FROM chats")
    print(cursor.fetchall())
    cursor.execute("SELECT * FROM messages")
    print(cursor.fetchall())
    cursor.execute("SELECT table_name FROM information_schema.tables WHERE table_schema NOT IN ("
                   "'information_schema', 'pg_catalog') AND table_schema IN('public', 'myschema');")
    print(cursor.fetchall())


def check_input(password: str, log: str):
    if len(log) < 5:
        messagebox.showerror('Input error', 'Login length must be more than 5 characters')
        return False
    if len(password) < 8:
        messagebox.showerror('Input error', 'Password does not meet the requirements')
        return False
    for i in password:
        if ord(i) < 45 or ord(i) > 122:
            messagebox.showerror('Input error', 'Unsupported symbols')
            return False
    for i in log:
        if ord(i) < 45 or ord(i) > 122:
            messagebox.showerror('Input error', 'Unsupported symbols')
            return False
    return True


# region API
def check_password(log, pas):
    try:
        return requests.get(f"{backend_url}auth?login={log}&password={pas}").json()
    except Exception as e:
        exception_handler(e)


def get_id(log):
    try:
        return requests.get(f"{backend_url}user/get_id?login={log}").json()
    except Exception as e:
        exception_handler(e)


def get_user_nickname(user):
    try:
        return requests.get(f"{backend_url}user/get_nickname?id={user}").json()
    except Exception as e:
        exception_handler(e)


def get_pubkey(user):
    try:
        return requests.get(f"{backend_url}user/get_pubkey?id={user}").json()
    except Exception as e:
        exception_handler(e)


def can_use_login(log):
    try:
        return requests.get(f"{backend_url}user/can_use_login?login={log}").json()
    except Exception as e:
        exception_handler(e)


def get_max_id():
    try:
        return requests.get(f"{backend_url}user/get_max_id").json()
    except Exception as e:
        exception_handler(e)


def regenerate_keys():
    root.update()
    global user_id, user_login, user_password
    try:
        if requests.put(f"{backend_url}user/update_pubkey", json={'login': user_login, 'password': user_password,
                                                                  'pubkey': keys_generation(),
                                                                  'user_id': user_id}).json():
            messagebox.showinfo("Success", "Regeneration successful!")
        else:
            messagebox.showerror("Failed", "Regeneration failed!")
    except Exception as e:
        exception_handler(e)


def get_chat_id(name: str):
    try:
        return requests.get(f"{backend_url}chat/get_id?name={name}").json()
    except Exception as e:
        exception_handler(e)


def get_chat_name(group_id: str):
    try:
        return requests.get(f"{backend_url}chat/get_name?group_id={group_id}").json()
    except Exception as e:
        exception_handler(e)


def get_chat_owner(group_id: str):
    try:
        return requests.get(f"{backend_url}chat/get_owner?group_id={group_id}").json()
    except Exception as e:
        exception_handler(e)


def get_users_groups(user):
    try:
        return requests.get(f"{backend_url}user/get_groups?user_id={user}").json()
    except Exception as e:
        exception_handler(e)


def get_chat_users(name: str):
    try:
        return requests.get(f"{backend_url}chat/get_users?{name}").json()
    except Exception as e:
        exception_handler(e)


# endregion


def auto_login():
    global user_login, user_id
    try:
        lgn = keyring.get_password('datachat', 'login')
        psw = keyring.get_password('datachat', 'password')
        if lgn is not None and psw is not None:
            entry_log.insert(0, lgn)
            entry_pass.insert(0, psw)
            var.set(1)
    except FileNotFoundError:
        pass
    except Exception as e:
        print(e)


def clear_auto_login():
    try:
        keyring.delete_password('datachat', 'login')
    except Exception:
        pass
    try:
        keyring.delete_password('datachat', 'password')
    except Exception:
        pass


def fill_auto_login_file(lgn, psw):
    keyring.set_password('datachat', 'login', lgn)
    keyring.set_password('datachat', 'password', psw)


def login(*args):
    global user_login, user_id, time_to_check, user_password
    label_loading.place(x=60, y=60)
    root.update()
    try:
        if len(entry_log.get()) == 0 or len(entry_pass.get()) == 0:
            messagebox.showerror('Input error', 'Fill all input fields')
            label_loading.place_forget()
            return
        res = check_password(entry_log.get(), entry_pass.get())
        user_password = entry_pass.get()
        if res is None:
            messagebox.showerror('Input error', 'User not found')
            label_loading.place_forget()
            return
        elif not res:
            msg = messagebox.askquestion('Input error', 'Wrong password, recover?', icon='error')
            if msg == 'yes':
                pass_code()
            label_loading.place_forget()
            return
        if var.get() == 0:
            clear_auto_login()
        else:
            fill_auto_login_file(entry_log.get(), entry_pass.get())
        user_login = entry_log.get()
        user_id = get_id(user_login)
        get_private_key()
        hide_auth_menu()
        label_loading.place_forget()
        checker.start()
        upd = keyring.get_password('datachat', 'update')
        if upd is not None:
            time_to_check = int(upd)
        qr = qrcode.make(private_key)
        qr.save(files_dir + '/QR.png')
        qr = Image.open(files_dir + '/QR.png')
        width = int(qr.size[0] / 2)
        height = int(qr.size[1] / 2)
        img = qr.resize((width, height), Image.ANTIALIAS)
        img.save(files_dir + '/QR.png')
        _qr = PhotoImage(file=files_dir + "/QR.png")
        label_qr = Label(main1_frame, image=_qr)
        label_qr.image = _qr
        # label_qr.pack(side=RIGHT, anchor=SE) # задумка на будущее
        os.remove(files_dir + '/QR.png')
    except Exception as e:
        label_loading.place_forget()
        exception_handler(e)


def show_reg_frame():
    root.geometry("200x175+{}+{}".format(w, h))
    button_login.pack_forget()
    button_reg_m.pack_forget()
    check_remember.pack_forget()
    label_email.pack(side=TOP, anchor=S)
    entry_email.pack(side=TOP)
    button_login_b.pack(side=LEFT, pady=3, anchor=CENTER)
    button_reg.pack(side=RIGHT, pady=3, anchor=CENTER)


def back_to_login():
    label_email.pack_forget()
    entry_email.pack_forget()
    button_login_b.pack_forget()
    button_reg.pack_forget()
    root.geometry("200x160+{}+{}".format(w, h))
    check_remember.pack(side=TOP, anchor=S)
    button_login.pack(side=LEFT, pady=3, anchor=CENTER)
    button_reg_m.pack(side=RIGHT, pady=3, anchor=CENTER)


def register():
    root.update()
    try:
        psw = entry_pass.get()
        lgn = entry_log.get()
        mail = entry_email.get()
        if len(lgn) == 0 or len(psw) == 0:
            messagebox.showerror('Input error', 'Fill all input fields')
            return
        if len(mail) <= 8 or ' ' in mail or '@' not in mail or '.' not in mail:
            messagebox.showerror('Input error', 'Enter valid email')
            return
        if not check_input(psw, lgn):
            return
        try:
            if not can_use_login(lgn):
                messagebox.showerror('Input error', 'User already register')
                return
        except Exception as e:
            print(e)
        hashed_pass = bcrypt.hashpw(psw.encode('utf-8'), bcrypt.gensalt())
        hashed_pass = str(hashed_pass)[2:-1]
        res = requests.post(f"{backend_url}user/create", json={'login': lgn, 'password': hashed_pass,
                                                               'pubkey': keys_generation(), 'email': mail}).json()
        if res:
            messagebox.showinfo("Success", "Register success!")
        else:
            messagebox.showerror("Failed", "Register failed!")
    except Exception as e:
        exception_handler(e)


def hide_auth_menu():
    global w, h
    root.update()
    w -= 200
    auth_frame.pack_forget()
    root.geometry("1000x500+{}+{}".format(w, h))
    entry_msg.focus_set()
    menu_frame.pack(side=LEFT, pady=5, anchor=N)
    main_frame.pack(side=LEFT, anchor=CENTER)


def menu_navigation(menu: str):
    global current_chat, chats, spacing, spacing_2, private_key, user_id, pin_chats
    if menu == "chat":
        for key in chats:
            chats[key].pack_forget()
        button_chat.pack(side=TOP, anchor=N)
        button_info.pack(side=TOP, pady=5, anchor=N)
        button_settings.pack(side=TOP, anchor=N)
        button_groups.pack(side=TOP, pady=5, anchor=N)
        if len(pin_chats) != 0:
            label_line1.pack(side=TOP, anchor=N)
            label_fixed.pack(side=TOP, anchor=N)
            for i in range(len(pin_chats)):
                if i % 2 == 0:
                    pin_chats[i].pack(side=TOP, pady=5, anchor=N)
                else:
                    pin_chats[i].pack(side=TOP, anchor=N)
            label_line2.pack(side=TOP, anchor=N)
        button_logout.pack(side=TOP, pady=5, anchor=N)
        button_back.pack_forget()
        button_chat.configure(bg="#2E8B57")
        button_info.configure(bg="#A9A9A9")
        button_settings.configure(bg="#A9A9A9")
        button_groups.configure(bg="#A9A9A9")
        main1_frame.pack_forget()
        settings_frame.pack_forget()
        group_frame.pack_forget()
        main_frame.pack(side=LEFT, anchor=CENTER)
        canvas.delete("all")
        current_chat = "-1"
        label_chat_id.configure(text='Current chat with: ')
        entry_chat_id.delete(0, tk.END)
        spacing, spacing_2 = 0, 0
        button_send2.configure(state='disabled')
        button_img2.configure(state='disabled')
    elif menu == "set":
        button_chat.configure(bg="#A9A9A9")
        button_info.configure(bg="#A9A9A9")
        button_settings.configure(bg="#2E8B57")
        button_groups.configure(bg="#A9A9A9")
        main_frame.pack_forget()
        main1_frame.pack_forget()
        group_frame.pack_forget()
        settings_frame.pack(side=LEFT, anchor=N)
    elif menu == "info":
        root.update()
        button_chat.configure(bg="#A9A9A9")
        button_info.configure(bg="#2E8B57")
        button_settings.configure(bg="#A9A9A9")
        button_groups.configure(bg="#A9A9A9")
        main_frame.pack_forget()
        settings_frame.pack_forget()
        group_frame.pack_forget()
        main1_frame.pack(side=LEFT, anchor=NW)
    elif menu == "group":
        button_chat.pack_forget()
        button_settings.pack_forget()
        button_info.pack_forget()
        label_fixed.pack_forget()
        label_line1.pack_forget()
        label_line2.pack_forget()
        for i in pin_chats:
            i.pack_forget()
        button_logout.pack_forget()
        button_groups.pack_forget()
        main_frame.pack_forget()
        main1_frame.pack_forget()
        settings_frame.pack_forget()
        groups = get_users_groups(user_id)
        counter = 0
        for i in groups:
            counter += 1
            chats[i] = tk.Button(menu_frame, text=i, bg='#A9A9A9', width=17)
            if counter % 2 == 0:
                chats[i].pack(side=TOP, anchor=N)
            else:
                chats[i].pack(side=TOP, pady=5, anchor=N)
        config(groups)
        group_frame.pack(side=LEFT, anchor=CENTER)
        if counter % 2 == 0:
            button_back.pack(side=TOP, pady=5, anchor=N)
        else:
            button_back.pack(side=TOP, anchor=N)


def config(groups):
    global chats
    root.update()
    try:
        chats[groups[0]].configure(command=lambda: change_group(get_chat_id(groups[0]), chats[groups[0]]))
    except IndexError:
        pass
    try:
        chats[groups[1]].configure(command=lambda: change_group(get_chat_id(groups[1]), chats[groups[1]]))
    except IndexError:
        pass
    try:
        chats[groups[2]].configure(command=lambda: change_group(get_chat_id(groups[2]), chats[groups[2]]))
    except IndexError:
        pass
    try:
        chats[groups[3]].configure(command=lambda: change_group(get_chat_id(groups[3]), chats[groups[3]]))
    except IndexError:
        pass
    try:
        chats[groups[4]].configure(command=lambda: change_group(get_chat_id(groups[4]), chats[groups[4]]))
    except IndexError:
        pass


def change_group(gr_id: str, button):
    button_send2.configure(state='normal')
    button_img2.configure(state='normal')
    global current_chat, chats
    current_chat = gr_id
    for key in chats:
        chats[key].configure(bg='#A9A9A9')
    button.configure(bg="#2E8B57")
    get_chat_message()


def get_user_info():
    root.update()
    try:
        _input = entry_id_or_nick.get()
        if _input.isdigit():
            res = get_user_nickname(int(_input))
        elif _input[-3:] == '_gr':
            res = get_chat_id(_input)
        else:
            res = get_id(_input)
        if res is None:
            messagebox.showerror('Input error', 'User not found')
            return
        entry_res.configure(state='normal')
        entry_res.delete(0, tk.END)
        entry_res.insert(0, res)
        entry_res.configure(state='disabled')
    except Exception as e:
        exception_handler(e)


def send_message():
    global user_id, current_chat
    root.update()
    try:
        if len(entry_msg.get()) == 0:
            messagebox.showerror('Input error', 'Fill all input fields')
            return
        for i in entry_msg.get():
            if ord(i) < 32 or ord(i) > 1366:
                messagebox.showerror('Input error', 'Unsupported symbols')
                return
        to_id = current_chat
        msg = entry_msg.get()
        encrypt_msg = encrypt(msg.encode('utf-8'), get_pubkey(to_id))
        encrypt_msg1 = encrypt(msg.encode('utf-8'), get_pubkey(user_id))
        date = datetime.utcnow().strftime('%y-%m-%d %H:%M:%S')
        requests.post(f"{backend_url}message/send", json={"date": date, "sender": user_id,
                                                          "destination": to_id, "message": encrypt_msg,
                                                          "message1": encrypt_msg1}).json()
        entry_msg.delete(0, tk.END)
        get_message()
    except Exception as e:
        exception_handler(e)


def send_doc():
    root.update()
    global user_id, current_chat, y
    connect, cursor = pg_connect()
    try:
        path = filedialog.askopenfilename(filetypes=[("All files", "*.*")])
        if len(path) == 0:
            return
        shutil.copy(r'{0}'.format(path), r'{0}'.format(os.path.abspath("")))
        path = path.split('/')
        path = path[len(path) - 1]
        try:
            y.upload(path, '/' + path)
        except Exception:
            pass
        link = y.get_download_link('/' + path)
        encrypt_msg = encrypt('՗'.encode('utf-8'), get_pubkey(current_chat))
        date = datetime.utcnow().strftime('%d/%m/%y %H:%M:%S')
        cursor.execute("INSERT INTO messages VALUES (to_timestamp('{0}', 'dd-mm-yy hh24:mi:ss'), '{1}', '{2}', "
                       "{3}, {3}, '{4}', 0)".format(date, user_id, current_chat, encrypt_msg, link))
        connect.commit()
        cursor.close()
        connect.close()
        os.remove(path)
        get_message()
    except Exception as e:
        exception_handler(e, connect, cursor)


def get_message():
    root.update()
    global user_id, spacing, current_chat
    spacing, nick = 0, 0
    res = requests.get(f"{backend_url}message/get?user_id={user_id}&chat_id={current_chat}&is_chat=0").json()
    try:
        canvas.delete("all")
        for i in range(2000):
            try:
                message = res[f"item_{i}"]
                if nick == 0:
                    nick = get_user_nickname(message["from_id"])
                decrypt_msg = decrypt(int2bytes(message["message"]), int2bytes(message["message1"]))
                date = datetime.strptime(message["date"], "%Y-%m-%dT%H:%M:%S")
                if decrypt_msg is None or ord(decrypt_msg[0]) == 1367:
                    author = f'{str(date + utc_diff)[2:]} {nick}:'
                    content = f'{message["file"]}'
                    msg_frame = Frame(canvas)
                    widget = tk.Listbox(msg_frame, bg='white', fg='black', font=14, width=95, height=1)
                    widget.insert(0, content)
                    widget2 = tk.Label(msg_frame, bg='white', fg='black', text=author, font=14)
                    widget2.pack(side=LEFT)
                    widget.pack(side=LEFT)
                    canvas.create_window(0, spacing, window=msg_frame, anchor='nw')
                    spacing += 25
                else:
                    content = f'{str(date + utc_diff)[2:]} {nick}: {decrypt_msg}'
                    widget = Label(canvas, text=content, bg='white', fg='black', font=14)
                    canvas.create_window(0, spacing, window=widget, anchor='nw')
                    spacing += 25
            except KeyError:
                break
        canvas.config(scrollregion=canvas.bbox("all"))
    except Exception as er:
        exception_handler(er)


def encrypt(msg: bytes, pubkey):
    try:
        pubkey = pubkey.split(', ')
        pubkey = rsa.PublicKey(int(pubkey[0]), int(pubkey[1]))
        encrypt_message = rsa.encrypt(msg, pubkey)
        return bytes2int(encrypt_message)
    except Exception as e:
        print(e)


def decrypt(msg: bytes, msg1: bytes):  # переписать
    global private_key
    try:
        decrypted_message = rsa.decrypt(msg, private_key)
        return decrypted_message.decode('utf-8')
    except Exception:
        try:
            decrypted_message = rsa.decrypt(msg1, private_key)
            return decrypted_message.decode('utf-8')
        except Exception:
            return None


def login_handler(*args):
    if len(entry_log.get()) == 0:
        messagebox.showerror('Input error', 'Fill all input fields')
        return
    elif len(entry_pass.get()) != 0:
        login()
    else:
        entry_pass.focus_set()


def send_message_handler(*args):
    if str(root.focus_get()) == ".!labelframe2.!entry":
        if len(entry_msg.get()) != 0:
            send_message()
        elif len(entry_msg.get()) == 0:
            entry_msg.focus_set()
    elif str(root.focus_get()) == ".!labelframe2.!entry2":
        if len(entry_msg.get()) != 0:
            send_message()
        elif len(entry_msg.get()) == 0:
            pass


def change_pass_handler(*args):
    if str(root.focus_get()) == ".!labelframe3.!labelframe3.!labelframe.!entry":
        if len(entry_old_pass.get()) != 0:
            entry_new_pass.focus_set()
            return
        elif len(entry_old_pass.get()) != 0 and len(entry_new_pass.get()) != 0:
            change_password()
            return
    elif str(root.focus_get()) == ".!labelframe3.!labelframe3.!labelframe2.!entry":
        if len(entry_new_pass.get()) == 0:
            messagebox.showerror("Input error", "Fill all input fields")
            return
        elif len(entry_old_pass.get()) == 0:
            entry_old_pass.focus_set()
            return
        elif len(entry_old_pass.get()) != 0 and len(entry_new_pass.get()) != 0:
            change_password()
            return


def keys_generation():
    global private_key
    try:
        (pubkey, privkey) = rsa.newkeys(1024)
        pubkey = str(pubkey)[10:-1]
        keyring.set_password('datachat', 'private_key', privkey.save_pkcs1().decode('ascii'))
        private_key = privkey
        return pubkey
    except Exception as e:
        print(e)


def get_private_key():
    try:
        global private_key
        private_key = rsa.PrivateKey.load_pkcs1(keyring.get_password('datachat', 'private_key'))
    except FileNotFoundError:
        pass


def create_chat():
    global user_id
    root.update()
    try:
        name = entry_chat.get()
        if len(name) < 5:
            messagebox.showerror("Input error", "Name lenght must be more than 5 characters")
            return
        if name[-3:] != '_gr':
            messagebox.showerror("Input error", "Name must contain '_gr' in the end")
            return
        for i in name:
            if ord(i) < 45 or ord(i) > 122:
                messagebox.showerror('Input error', 'Unsupported symbols')
                return
        res = requests.post(f"{backend_url}chat/create", json={"name": name, "owner": user_id})
        if res:
            messagebox.showinfo('Success', 'Chat created')
            return
        elif res is None:
            messagebox.showerror('Name error', 'Name exists')
            return
        else:
            messagebox.showerror('Unknown error', 'oooops!')
    except Exception as e:
        exception_handler(e)


def send_chat_message():
    global user_id, current_chat
    root.update()
    message = entry_msg2.get()
    try:
        if len(message) == 0:
            messagebox.showerror('Input error', 'Fill all input fields')
            return
        name = get_chat_name(current_chat)
        users = get_chat_users(name)
        for i in users:
            encrypt_msg = encrypt(message.encode('utf-8'), get_pubkey(i[0]))
            date = datetime.utcnow().strftime('%d/%m/%y %H:%M:%S')
            requests.post(f"{backend_url}message/send/chat", json={"date": date,
                                                                   "sender": f"{current_chat}_{user_id}",
                                                                   "destination": i[0], "message": encrypt_msg})
            entry_msg2.delete(0, tk.END)
        get_chat_message()
    except Exception as e:
        exception_handler(e)


def send_chat_doc():
    global user_id, current_chat, y
    root.update()
    connect, cursor = pg_connect()
    try:
        path = filedialog.askopenfilename(filetypes=[("All files", "*.*")])
        if len(path) == 0:
            cursor.close()
            connect.close()
            return
        shutil.copy(r'{0}'.format(path), r'{0}'.format(os.path.abspath("")))
        path = path.split('/')
        path = path[len(path) - 1]
        try:
            y.upload(path, '/' + path)
        except Exception:
            pass
        link = y.get_download_link('/' + path)
        name = get_chat_name(current_chat)
        users = get_chat_users(name)
        for i in users:
            cursor.execute("SELECT pubkey FROM users WHERE id={0}".format(i[0]))
            res = cursor.fetchall()[0][0]
            encrypt_msg = psycopg2.Binary(encrypt('՗'.encode('utf-8'), res))
            date = datetime.utcnow().strftime('%d/%m/%y %H:%M:%S')
            cursor.execute(
                "INSERT INTO messages VALUES (to_timestamp('{0}', 'yy-mm-dd hh24:mi:ss'), '{1}', '{2}', {3}, {3},"
                "'{4}', 0)".format(date, current_chat + '_' + str(user_id), i[0], encrypt_msg, link))
        connect.commit()
        cursor.close()
        os.remove(path)
        connect.close()
        get_chat_message()
    except Exception as e:
        exception_handler(e, connect, cursor)


def get_chat_message():
    global user_id, spacing_2, current_chat
    canvas_2.delete("all")
    spacing_2 = 0
    res = requests.get(f"{backend_url}message/get?user_id={user_id}&chat_id={current_chat}&is_chat=1").json()
    try:
        for i in range(2000):
            try:
                message = res[f"item_{i}"]
                decrypt_msg = decrypt(int2bytes(message["message"]), int2bytes(message["message1"]))
                date = datetime.strptime(message["date"], "%Y-%m-%dT%H:%M:%S")
                nickname = get_user_nickname(message["from_id"].split('_', 1)[1])
                if decrypt_msg is None or ord(decrypt_msg[0]) == 1367:
                    author = f'{str(date + utc_diff)[2:]} {nickname}:'
                    content = f'{message["file"]}'
                    msg_frame = Frame(canvas_2)
                    widget = tk.Listbox(msg_frame, bg='white', fg='black', font=14, width=95, height=1)
                    widget.insert(0, content)
                    widget2 = tk.Label(msg_frame, bg='white', fg='black', text=author, font=14)
                    widget2.pack(side=LEFT)
                    widget.pack(side=LEFT)
                    canvas_2.create_window(0, spacing_2, window=msg_frame, anchor='nw')
                    spacing_2 += 25
                else:
                    content = f'{str(date + utc_diff)[2:]} {nickname}: {decrypt_msg}'
                    widget = Label(canvas_2, text=content, bg='white', fg='black', font=14)
                    canvas_2.create_window(0, spacing_2, window=widget, anchor='nw')
                    spacing_2 += 25
            except KeyError:
                break
        canvas_2.config(scrollregion=canvas_2.bbox("all"))
    except Exception as e:
        exception_handler(e)


def invite_to_group():
    global user_id
    root.update()
    inv_user = entry_inv_id.get()
    inv_group = entry_gr_toinv.get()
    if len(inv_user) == 0 and len(inv_group) == 0:
        messagebox.showerror('Input error', 'Entries lenght must be more than 0 characters')
        return
    try:
        if user_id != int(get_chat_owner(inv_group)):
            messagebox.showerror('Access error', "You are not chat's owner")
            return
        groups = get_users_groups(inv_user)
        name = get_chat_name(inv_group)
        if name in groups:
            messagebox.showerror('Input error', "Пользователь уже состоит в группе")
            return
        requests.post(f"{backend_url}chat/invite", json={"name": name, "user": int(inv_user)})
        messagebox.showinfo('Success', "Success")
    except Exception as e:
        exception_handler(e)


def kick_from_group():
    global user_id
    root.update()
    kick_user = entry_kick_id.get()
    kick_group = entry_gr_tokick.get()
    if len(kick_user) == 0 and len(kick_group) == 0:
        messagebox.showerror('Input error', 'Entries lenght must be more than 0 characters')
        return
    try:
        if user_id != int(get_chat_owner(kick_group)):
            messagebox.showerror('Access error', "You are not chat's owner")
            return
        groups = get_users_groups(kick_user)
        name = get_chat_name(kick_group)
        if name not in groups:
            messagebox.showerror('Input error', "User is not in group")
            return
        requests.post(f"{backend_url}chat/kick", json={"name": name, "user": int(kick_user)})
        messagebox.showinfo('Success', "Success")
    except Exception as e:
        exception_handler(e)


def logout():
    global w, h
    w += 200
    menu_navigation("chat")
    menu_frame.pack_forget()
    main_frame.pack_forget()
    root.geometry("200x160+{}+{}".format(w, h))
    entry_log.focus_set()
    auth_frame.pack(side=TOP, anchor=CENTER)


def recovery_menu():
    global w, h, code
    try:
        auth_frame.pack_forget()
        root.geometry("200x100+{}+{}".format(w, h))
        recovery_frame.pack(side=TOP, anchor=CENTER)
    except Exception as e:
        print(e)


def new_pass_menu():
    global w, h, user_login, code
    try:
        code = entry_code.get()
        res = requests.post(f"{backend_url}recovery/validate", json={"code": entry_code.get(),
                                                                     "login": user_login}).json
        if not res:
            messagebox.showerror('Input error', 'Incorrect code')
            return
        recovery_frame.pack_forget()
        root.geometry("200x130+{}+{}".format(w, h))
        new_pass_frame.pack(side=TOP, anchor=CENTER)
    except Exception as e:
        print(e)


def change_password():
    global user_login
    root.update()
    try:
        hashed_pass = bcrypt.hashpw(entry_new_pass.get().encode('utf-8'), bcrypt.gensalt())
        hashed_pass = str(hashed_pass)[2:-1]
        response = requests.put(f"{backend_url}user/update_password", json={"login": user_login,
                                                                            "old_password": entry_old_pass.get(),
                                                                            "new_password": hashed_pass}).json()
        if response:
            messagebox.showinfo("Success", "Password has been changed")
            fill_auto_login_file(user_login, entry_new_pass.get())
            return
        elif response is None:
            messagebox.showerror('Input error', 'User not found')
            return
        else:
            messagebox.showerror("Input error", "Current password is wrong")
    except Exception as e:
        exception_handler(e)


def set_new_pass():
    global user_login, email, code
    root.update()
    user_login = entry_log.get()
    try:
        if check_input(entry_new_p2.get(), entry_new_p.get()):
            if entry_new_p.get() == entry_new_p2.get():
                hashed_pass = bcrypt.hashpw(entry_new_p.get().encode('utf-8'), bcrypt.gensalt())
                hashed_pass = str(hashed_pass)[2:-1]
                res = requests.post(f"{backend_url}recovery/validate", json={"code": code,
                                                                             "login": email,
                                                                             "password": hashed_pass}).json()
                if res:
                    messagebox.showinfo("Success", "Password has been changed")
                    fill_auto_login_file(user_login, entry_new_p.get())
                    entry_pass.delete(0, tk.END)
                    entry_pass.insert(0, entry_new_p.get())
                    root.geometry("200x160+{}+{}".format(w, h))
                    new_pass_frame.pack_forget()
                    auth_frame.pack(side=TOP, anchor=CENTER)
                else:
                    messagebox.showerror("Success", "Password has not been changed")
    except Exception as e:
        exception_handler(e)


def pass_code():
    root.update()
    try:
        res = requests.post(f"{backend_url}recovery?login={entry_log.get()}").json()
        if res:
            messagebox.showinfo('Recovery', 'Recovery code has been sent to your email')
            recovery_menu()
            return
        elif res is None:
            messagebox.showwarning('Recovery', 'User not found')
            return
        else:
            messagebox.showerror('Recovery', 'Recovery code has not been sent')
    except Exception as e:
        exception_handler(e)


def open_chat(chat_id):
    global current_chat
    root.update()
    chat = chat_id
    if len(chat) == 0 or not chat.isnumeric():
        messagebox.showerror('Input error', 'Chat id must be a number')
        return
    nick = get_user_nickname(int(chat))
    if nick is not None:
        label_chat_id.configure(text='Current chat with: ' + nick)
    else:
        messagebox.showerror('Input error', 'User not found')
        return
    current_chat = chat
    button_send.configure(state='normal')
    button_img.configure(state='normal')
    canvas.delete("all")
    get_message()


def pin_chat():
    try:
        user = entry_pin.get()
        if len(user) == 0:
            messagebox.showerror('Input error', 'Empty input')
            return
        name = get_user_nickname(user)
        info = user + ' ' + name
        pin1 = keyring.get_password('datachat', 'pin1')
        if pin1 is None:
            keyring.set_password('datachat', 'pin1', info)
            return
        pin2 = keyring.get_password('datachat', 'pin2')
        if pin2 is None:
            keyring.set_password('datachat', 'pin2', info)
            return
        pin3 = keyring.get_password('datachat', 'pin3')
        if pin3 is None:
            keyring.set_password('datachat', 'pin3', info)
            return
        messagebox.showerror('Pin error', 'Pin limit')
    except Exception as e:
        exception_handler(e)


def unpin_chat(chat, frame):
    try:
        pin_chats.remove(frame)
        messagebox.showerror('В разработке', 'кнопка имеет неполный функционал')
        frame.pack_forget()
    except Exception as e:
        print(e)


def pin_constructor(text, chat):
    try:
        local_frame = tk.LabelFrame(menu_frame, width=150, height=50, relief=FLAT)
        button1 = tk.Button(local_frame, text=text, bg='#A9A9A9', width=13, command=lambda:
        (menu_navigation("chat"), open_chat(chat)))
        button2 = tk.Button(local_frame, text='-', bg='#B00000', width=2, command=lambda: unpin_chat(chat, local_frame))
        button1.pack(side=LEFT, anchor=N)
        button2.pack(side=LEFT, anchor=N, padx=3)
        local_frame.pack(side=TOP, pady=1, anchor=N)
        pin_chats.append(local_frame)
    except Exception as e:
        print(e)


def get_pin_chats():
    global pin_chats
    try:
        pin1 = keyring.get_password('datachat', 'pin1')
        if pin1 is None:
            label_fixed.pack_forget()
            label_line1.pack_forget()
            label_line2.pack_forget()
            return
        pin1 = pin1.split()
        pin_constructor(pin1[1], pin1[0])
        pin2 = keyring.get_password('datachat', 'pin2')
        if pin2 is None:
            return
        pin2 = pin2.split()
        pin_constructor(pin2[1], pin2[0])
        pin3 = keyring.get_password('datachat', 'pin3')
        if pin3 is None:
            return
        pin3 = pin3.split()
        pin_constructor(pin3[1], pin3[0])
    except Exception as e:
        print(e)


def OnMouseWheel(event):
    canvas.yview("scroll", event.delta, "units")
    return "break"


def auto_check():
    global time_to_check
    if time_to_check == 30:
        time_to_check = 45
        label_check2.configure(text='45 Sec')
    elif time_to_check == 45:
        time_to_check = 60
        label_check2.configure(text='1 Min')
    elif time_to_check == 60:
        time_to_check = -1
        label_check2.configure(text='Never')
    elif time_to_check == -1:
        time_to_check = 30
        label_check2.configure(text='30 Sec')
    keyring.set_password('datachat', 'update', time_to_check)


def loop_get_msg():
    global time_to_check
    timing = time.time()
    while True:
        if time_to_check > 0:
            if time.time() - timing > time_to_check:
                timing = time.time()
                res = requests.get(f"{backend_url}message/loop?user_id={user_id}").json()
                if res is not None:
                    messagebox.showinfo('New messages!', 'You have new messages in chats: ' + res)
                if current_chat != '-1':
                    if current_chat[0] != 'g':
                        get_message()
                    elif current_chat[0] == 'g':
                        get_chat_message()


def api_awake():
    requests.get(f"{backend_url}api/awake")


awake_thread = threading.Thread(target=api_awake, daemon=True)
awake_thread.start()


# region auth
auth_frame = LabelFrame(root, width=200, height=130, relief=FLAT)
auth_frame.pack(side=TOP, anchor=CENTER)
label_user = tk.Label(auth_frame, font=10, text="Username:                       ", fg="black", width=18)
label_user.pack(side=TOP, anchor=S)
entry_log = tk.Entry(auth_frame, font=12, width=20, fg="black")
entry_log.bind("<Return>", login_handler)
entry_log.pack(side=TOP)
label_password = tk.Label(auth_frame, font=10, text="Password:                       ", fg="black", width=18)
label_password.pack(side=TOP, anchor=S)
entry_pass = tk.Entry(auth_frame, font=12, width=20, fg="black", show='•')
entry_pass.bind("<Return>", login)
entry_pass.pack(side=TOP)
check_remember = tk.Checkbutton(auth_frame, font=10, fg='black', text='Remember me', variable=var)
check_remember.pack(side=TOP, anchor=S)
button_login = tk.Button(auth_frame, text="LOGIN", bg='#2E8B57', width=11, command=lambda: login())
button_login.pack(side=LEFT, pady=3, anchor=CENTER)
button_reg_m = tk.Button(auth_frame, text="REGISTER", bg='#2E8B57', width=11, command=lambda: show_reg_frame())
button_reg_m.pack(side=RIGHT, pady=3, anchor=CENTER)
button_reg = tk.Button(auth_frame, text="REGISTER", bg='#2E8B57', width=11, command=lambda: register())
button_login_b = tk.Button(auth_frame, text="BACK", bg='#2E8B57', width=11, command=lambda: back_to_login())
# endregion
# region reg
recovery_frame = LabelFrame(root, width=200, height=130, relief=FLAT)
label_code = tk.Label(recovery_frame, font=10, text="Code:                           ", fg="black", width=18)
label_code.pack(side=TOP, anchor=S)
entry_code = tk.Entry(recovery_frame, font=12, width=20, fg="black")
entry_code.pack(side=TOP)
button_code = tk.Button(recovery_frame, text="SEND", bg='#2E8B57', width=11, command=lambda: new_pass_menu())
button_code.pack(side=RIGHT, pady=3, anchor=CENTER)
# endregion
# region new pass
new_pass_frame = LabelFrame(root, width=200, height=130, relief=FLAT)
label_code = tk.Label(new_pass_frame, font=10, text="New Password:              ", fg="black", width=18)
label_code.pack(side=TOP, anchor=S)
entry_new_p = tk.Entry(new_pass_frame, font=12, width=20, fg="black", show='•')
entry_new_p.pack(side=TOP)
label_code = tk.Label(new_pass_frame, font=10, text="Repeat Password:           ", fg="black", width=18)
label_code.pack(side=TOP, anchor=S)
entry_new_p2 = tk.Entry(new_pass_frame, font=12, width=20, fg="black", show='•')
entry_new_p2.pack(side=TOP)
button_code = tk.Button(new_pass_frame, text="SET", bg='#2E8B57', width=11, command=lambda: set_new_pass())
button_code.pack(side=RIGHT, pady=3, anchor=CENTER)
# endregion
# region email
label_email = tk.Label(auth_frame, font=10, text="Email:                          ", fg="black", width=18)
entry_email = tk.Entry(auth_frame, font=12, width=20, fg="black")
# endregion
# region main menu
main_frame = LabelFrame(root, width=850, height=500)
group_frame = LabelFrame(root, width=850, height=500)
settings_frame = LabelFrame(root, width=600, height=500)
menu_frame = LabelFrame(root, width=150, height=500, relief=FLAT)
button_chat = tk.Button(menu_frame, text="CHAT", bg='#2E8B57', width=17, command=lambda: menu_navigation("chat"))
button_chat.pack(side=TOP, anchor=N)
button_info = tk.Button(menu_frame, text="INFO", bg='#A9A9A9', width=17, command=lambda: menu_navigation("info"))
button_info.pack(side=TOP, pady=5, anchor=N)
button_settings = tk.Button(menu_frame, text="SETTINGS", bg='#A9A9A9', width=17, command=lambda: menu_navigation("set"))
button_settings.pack(side=TOP, anchor=N)
button_groups = tk.Button(menu_frame, text="GROUPS", bg='#A9A9A9', width=17, command=lambda: menu_navigation("group"))
button_groups.pack(side=TOP, pady=5, anchor=N)
label_line1 = tk.Label(menu_frame, font=16, text="-------------------------", fg="black")
label_line1.pack(side=TOP, anchor=N)
label_fixed = tk.Label(menu_frame, font=8, text="PIN CHATS", fg="black")
label_fixed.pack(side=TOP, anchor=N)
get_pin_chats()
label_line2 = tk.Label(menu_frame, font=16, text="-------------------------", fg="black")
label_line2.pack(side=TOP, anchor=N)
button_logout = tk.Button(menu_frame, text="LOGOUT", bg='#B22222', width=17, command=lambda: logout())
button_logout.pack(side=BOTTOM, pady=5, anchor=N)
button_back = tk.Button(menu_frame, text="BACK", bg='#B22222', width=17, command=lambda: menu_navigation("chat"))
main2_frame = LabelFrame(main_frame, width=600, height=350, relief=FLAT)
main2_frame.pack(side=TOP, anchor=CENTER)
main2_frame2 = LabelFrame(group_frame, width=600, height=350, relief=FLAT)
main2_frame2.pack(side=TOP, anchor=CENTER)
# endregion
# region chat
chat_frame = LabelFrame(main2_frame, width=600, height=25, relief=FLAT)
chat_frame.pack(side=TOP, pady=2, anchor=N)
label_chat_id = tk.Label(chat_frame, font=10, text="Current chat with: ", fg="black", width=25, anchor=W)
label_chat_id.pack(side=LEFT, anchor=W)
entry_chat_id = tk.Entry(chat_frame, font=12, width=20, fg="black")
entry_chat_id.pack(side=LEFT, padx=165, anchor=CENTER)
button_chat_id = tk.Button(chat_frame, text="OPEN", bg='#2E8B57', width=15,
                           command=lambda: open_chat(entry_chat_id.get()))
button_chat_id.pack(side=RIGHT, anchor=E)

frame = Frame(main2_frame, width=850, height=450)
frame.pack(expand=True, fill=BOTH)
canvas = Canvas(frame, bg='#FFFFFF', width=850, height=370, scrollregion=(0, 0, 500, 450))
vbar = Scrollbar(frame, orient=VERTICAL)
vbar.pack(side=RIGHT, fill=Y)
vbar.config(command=canvas.yview)
hbar = Scrollbar(frame, orient=HORIZONTAL)
hbar.pack(side=BOTTOM, fill=X)
hbar.config(command=canvas.xview)
canvas.config(width=850, height=370)
canvas.config(xscrollcommand=hbar.set, yscrollcommand=vbar.set)
canvas.pack(side=TOP, expand=True, fill=BOTH)
canvas.bind("<MouseWheel>", OnMouseWheel)
canvas.config(scrollregion=canvas.bbox("all"))

frame_2 = Frame(main2_frame2, width=850, height=500)
frame_2.pack(expand=True, fill=BOTH)
canvas_2 = Canvas(frame_2, bg='#FFFFFF', width=850, height=410, scrollregion=(0, 0, 500, 500))
vbar_2 = Scrollbar(frame_2, orient=VERTICAL)
vbar_2.pack(side=RIGHT, fill=Y)
vbar_2.config(command=canvas_2.yview)
hbar_2 = Scrollbar(frame_2, orient=HORIZONTAL)
hbar_2.pack(side=BOTTOM, fill=X)
hbar_2.config(command=canvas_2.xview)
canvas_2.config(width=850, height=410)
canvas_2.config(xscrollcommand=hbar_2.set, yscrollcommand=vbar_2.set)
canvas_2.pack(side=TOP, expand=True, fill=BOTH)
canvas_2.bind("<MouseWheel>", OnMouseWheel)
canvas_2.config(scrollregion=canvas_2.bbox("all"))

button_refresh = tk.Button(main_frame, text="REFRESH", bg='#2E8B57', width=128, command=lambda: get_message())
button_refresh.pack(side=TOP, pady=3, anchor=CENTER)
entry_msg = tk.Entry(main_frame, font=10, width=85)
entry_msg.bind("<Return>", send_message_handler)
entry_msg.pack(side=LEFT, padx=3)
button_img = tk.Button(main_frame, text="➕", bg='#2E8B57', width=3, command=lambda: send_doc(), state='disabled')
button_img.pack(side=LEFT, anchor=E)
button_send = tk.Button(main_frame, text="SEND", bg='#2E8B57', width=8, command=lambda: send_message(),
                        state='disabled')
button_send.pack(side=LEFT, anchor=E, padx=3)

button_refresh2 = tk.Button(group_frame, text="REFRESH", bg='#2E8B57', width=128, command=lambda: get_chat_message())
button_refresh2.pack(side=TOP, pady=3, anchor=CENTER)
entry_msg2 = tk.Entry(group_frame, font=10, width=85)
# entry_msg2.bind("<Return>", send_chat_message())
entry_msg2.pack(side=LEFT, padx=3)
button_img2 = tk.Button(group_frame, text="➕", bg='#2E8B57', width=3, state='disabled', command=lambda: send_chat_doc())
button_img2.pack(side=LEFT, anchor=E)
button_send2 = tk.Button(group_frame, text="SEND", bg='#2E8B57', width=8, state='disabled',
                         command=lambda: send_chat_message())
button_send2.pack(side=LEFT, anchor=E, padx=3)
entry_log.focus_set()
# root.after(500, loop)
# endregion
# region settings
settings_frame_2 = LabelFrame(settings_frame, width=600, height=25, relief=FLAT)
settings_frame_2.pack(side=TOP, pady=2, anchor=N)
label_check = tk.Label(settings_frame_2, font=10, text="  Update frequency:", fg="black", width=18, anchor=W)
label_check.pack(side=LEFT, anchor=W)
label_check2 = tk.Label(settings_frame_2, font=12, text='1 min', width=20, fg="black")
label_check2.pack(side=LEFT, padx=170, anchor=CENTER)
button_check_msg = tk.Button(settings_frame_2, text="UPDATE", bg='#2E8B57', width=15, command=lambda: auto_check())
button_check_msg.pack(side=RIGHT, anchor=E)

settings_frame7 = LabelFrame(settings_frame, width=600, height=25, relief=FLAT)
settings_frame7.pack(side=TOP, pady=2, anchor=N)
label_chat = tk.Label(settings_frame7, font=10, text="  Create chat:", fg="black", width=18, anchor=W)
label_chat.pack(side=LEFT, anchor=W)
entry_chat = tk.Entry(settings_frame7, font=12, width=20, fg="black")
entry_chat.pack(side=LEFT, padx=170, anchor=CENTER)
button_c_chat = tk.Button(settings_frame7, text="CREATE", bg='#2E8B57', width=15, command=lambda: create_chat())
button_c_chat.pack(side=RIGHT, anchor=E)

settings_frame11 = LabelFrame(settings_frame, width=600, height=25, relief=FLAT)
settings_frame11.pack(side=TOP, pady=2, anchor=N)
label_pin = tk.Label(settings_frame11, font=10, text="  Pin chat:", fg="black", width=18, anchor=W)
label_pin.pack(side=LEFT, anchor=W)
entry_pin = tk.Entry(settings_frame11, font=12, width=20, fg="black")
entry_pin.pack(side=LEFT, padx=170, anchor=CENTER)
button_pin = tk.Button(settings_frame11, text="PIN", bg='#2E8B57', width=15, command=lambda: pin_chat())
button_pin.pack(side=RIGHT, anchor=E)

settings_frame8 = LabelFrame(settings_frame, width=600, height=25, relief=FLAT)
settings_frame8.pack(side=TOP, pady=2, anchor=N)
settings_frame9 = LabelFrame(settings_frame8, width=600, height=25, relief=FLAT)
settings_frame9.pack(side=LEFT, pady=2, anchor=N)
label_inv_id = tk.Label(settings_frame9, font=10, text="  ID to invite:", fg="black", width=18, anchor=W)
label_inv_id.pack(side=TOP, anchor=W)
entry_inv_id = tk.Entry(settings_frame9, font=12, width=20, fg="black")
entry_inv_id.pack(side=TOP, anchor=CENTER)
settings_frame10 = LabelFrame(settings_frame8, width=600, height=25, relief=FLAT)
settings_frame10.pack(side=LEFT, pady=2, padx=158, anchor=N)
label_gr_toinv = tk.Label(settings_frame10, font=10, text="Group id:", fg="black", width=18, anchor=W)
label_gr_toinv.pack(side=TOP, anchor=W)
entry_gr_toinv = tk.Entry(settings_frame10, font=12, width=20, fg="black")
entry_gr_toinv.pack(side=TOP, anchor=CENTER)
button_invite = tk.Button(settings_frame8, text="INVITE", bg='#2E8B57', width=15, command=lambda: invite_to_group())
button_invite.pack(side=RIGHT, anchor=S)

settings_frame20 = LabelFrame(settings_frame, width=600, height=25, relief=FLAT)
settings_frame20.pack(side=TOP, pady=2, anchor=N)
settings_frame21 = LabelFrame(settings_frame20, width=600, height=25, relief=FLAT)
settings_frame21.pack(side=LEFT, pady=2, anchor=N)
label_kick_id = tk.Label(settings_frame21, font=10, text="  ID to kick:", fg="black", width=18, anchor=W)
label_kick_id.pack(side=TOP, anchor=W)
entry_kick_id = tk.Entry(settings_frame21, font=12, width=20, fg="black")
entry_kick_id.pack(side=TOP, anchor=CENTER)
settings_frame10 = LabelFrame(settings_frame20, width=600, height=25, relief=FLAT)
settings_frame10.pack(side=LEFT, pady=2, padx=158, anchor=N)
label_gr_tokick = tk.Label(settings_frame10, font=10, text="Group id:", fg="black", width=18, anchor=W)
label_gr_tokick.pack(side=TOP, anchor=W)
entry_gr_tokick = tk.Entry(settings_frame10, font=12, width=20, fg="black")
entry_gr_tokick.pack(side=TOP, anchor=CENTER)
button_kick = tk.Button(settings_frame20, text="KICK", bg='#2E8B57', width=15, command=lambda: kick_from_group())
button_kick.pack(side=RIGHT, anchor=S)

settings_frame3 = LabelFrame(settings_frame, width=600, height=25, relief=FLAT)
settings_frame3.pack(side=TOP, pady=2, anchor=N)
settings_frame5 = LabelFrame(settings_frame3, width=600, height=25, relief=FLAT)
settings_frame5.pack(side=LEFT, pady=2, anchor=N)
label_old_pass = tk.Label(settings_frame5, font=10, text="  Current password:", fg="black", width=18, anchor=W)
label_old_pass.pack(side=TOP, anchor=W)
entry_old_pass = tk.Entry(settings_frame5, font=12, width=20, fg="black", show='•')
entry_old_pass.bind("<Return>", change_pass_handler)
entry_old_pass.pack(side=TOP, anchor=CENTER)
settings_frame6 = LabelFrame(settings_frame3, width=600, height=25, relief=FLAT)
settings_frame6.pack(side=LEFT, pady=2, padx=158, anchor=N)
label_new_pass = tk.Label(settings_frame6, font=10, text="New password:", fg="black", width=18, anchor=W)
label_new_pass.pack(side=TOP, anchor=W)
entry_new_pass = tk.Entry(settings_frame6, font=12, width=20, fg="black", show='•')
entry_new_pass.bind("<Return>", change_pass_handler)
entry_new_pass.pack(side=TOP, anchor=CENTER)
button_pass_font = tk.Button(settings_frame3, text="CHANGE", bg='#2E8B57', width=15, command=lambda: change_password())
button_pass_font.pack(side=RIGHT, anchor=S)

settings_frame4 = LabelFrame(settings_frame, width=600, height=25, relief=FLAT)
settings_frame4.pack(side=TOP, pady=2, anchor=N)
button_b_font = tk.Button(settings_frame4, text="REGENERATE ENCRYPTION KEYS", bg='#2E8B57', width=100,
                          command=lambda: regenerate_keys())
button_b_font.pack(side=TOP, anchor=CENTER)
# endregion
# region info
main1_frame = LabelFrame(root, width=600, height=350, relief=SUNKEN)
info_frame = LabelFrame(main1_frame, relief=SUNKEN)
info_frame.pack(side=LEFT, anchor=NW)
label_info = tk.Label(info_frame, font=10, text="ID/Nickname/Group", fg="black", width=18)
label_info.pack(side=TOP, anchor=SW)
entry_res = tk.Entry(info_frame, font=10, width=20, state='disabled')
entry_res.pack(side=TOP, padx=2, pady=3, anchor=SW)
entry_id_or_nick = tk.Entry(info_frame, font=10, width=20)
entry_id_or_nick.pack(side=TOP, padx=2, anchor=SW)
button_check = tk.Button(info_frame, text="CHECK", bg='#2E8B57', width=25, command=lambda: get_user_info())
button_check.pack(side=TOP, anchor=SW)
label_loading = Label(root, font=10, text="LOADING", fg="black", bg="white")
# endregion
auto_login()
checker = threading.Thread(target=loop_get_msg, daemon=True)

if __name__ == "__main__":
    root.title("Chat")
    root.geometry("200x160+{}+{}".format(w, h))
    root.resizable(False, False)
    root.mainloop()
