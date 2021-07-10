import json
import os
import platform
import pyminizip
import threading
import sched
import time
import tkinter as tk
import tkinter.ttk as ttk
from datetime import datetime, timezone
from tkinter import *
from tkinter import messagebox, filedialog
from tkinter.font import Font
import bcrypt
import keyring
import qrcode
import requests
import rsa
from PIL import Image
from keyring import errors
from keyring.backends.Windows import WinVaultKeyring
from keyring.backends.OS_X import Keyring
from rsa.transform import int2bytes, bytes2int

if platform.uname().system == "Windows":
    keyring.set_keyring(WinVaultKeyring())
    files_dir = os.getenv('APPDATA') + "\\PojiloiChat"
elif platform.uname().system == "Darwin":
    keyring.set_keyring(Keyring())
    files_dir = os.path.join(os.environ['HOME'], "PojiloiChat")

backend_url = "https://chat-b4ckend.herokuapp.com/"
chats, theme = {}, {}
pin_chats = []
current_chat = "-1"
root = tk.Tk()
spacing, spacing_2 = 0, 0
w = root.winfo_screenwidth() // 2 - 140
h = root.winfo_screenheight() // 2 - 100
code, user_id, email, user_login, user_password, access_token = '', '', '', '', '', ''
remember_var, theme_var = IntVar(), IntVar()
relief, frames_relief, cursors = StringVar(), StringVar(), StringVar()
private_key = rsa.PrivateKey(1, 2, 3, 4, 5)
time_to_check = 60.0
utc_diff = datetime.now(timezone.utc).astimezone().utcoffset()
sch = sched.scheduler(time.time, time.sleep)


def create_theme_file():
    theme_dict = {}
    theme_dict.update({"text_color": "#FFFFFF",
                       "entry": "#808080",
                       "relief": "flat",
                       "frame_relief": "flat",  # RIDGE
                       "bg": "#48494F",
                       "select_bg": "#000000",
                       "font_main": "Candara 13",
                       "font_users": "Candara 15",
                       "button_font": "Candara 10",
                       "button_bg": "#757575",
                       "button_bg_positive": "#006891",
                       "button_bg_negative": "#B22222",
                       "button_bg_active": "#757575",
                       "cursor": "pencil"})
    with open(files_dir + "/settings/theme.json", "w") as file:
        json.dump(theme_dict, file, indent=2)


def create_config_file():
    theme_dict = {}
    theme_dict.update({"theme": "0",
                       "pin1": None,
                       "pin2": None,
                       "pin3": None,
                       "update": 60})
    with open(files_dir + "/settings/config.json", "w") as file:
        json.dump(theme_dict, file, indent=2)


def folders():
    try:
        os.mkdir(files_dir)
    except FileExistsError:
        pass
    try:
        os.mkdir(files_dir + "\\temp")
    except FileExistsError:
        pass
    try:
        os.mkdir(files_dir + "\\cache")
    except FileExistsError:
        pass
    try:
        os.mkdir(files_dir + "\\settings")
        create_theme_file()
        create_config_file()
    except FileExistsError:
        pass


def set_theme(flag=None):
    global theme
    if flag is None:
        with open(files_dir + "/settings/config.json", "r") as file:
            temp = json.load(file)['theme']
    else:
        temp = flag
        with open(files_dir + "/settings/config.json", "r") as file:
            tmp = json.load(file)
        tmp['file'] = temp
        with open(files_dir + "/settings/config.json", "w") as file:
            json.dump(tmp, file, indent=2)
    if temp == 1:
        theme_var.set(1)
        theme = {"text_color": "#FFFFFF",
                 "entry": "#808080",
                 "relief": "flat",
                 "frame_relief": "flat",  # RIDGE
                 "bg": "#48494F",
                 "select_bg": "#000000",
                 "font_main": Font(family="Candara", size=13),
                 "font_users": Font(family="Candara", size=15),
                 "button_font": Font(family="Candara", size=10),
                 "button_bg": "#757575",
                 "button_bg_positive": "#006891",
                 "button_bg_negative": "#B22222",
                 "button_bg_active": "#757575",
                 "cursor": "pencil"}
    elif temp == 2:
        theme_var.set(2)
        try:
            with open(files_dir + "/settings/theme.json", "r") as file:
                theme = json.load(file)
        except Exception as er:
            messagebox.showerror("Custom theme error", str(er))
            exception_handler(er)
            set_theme(0)
    else:
        theme_var.set(0)
        theme = {"text_color": "#000000",
                 "entry": "#FFFFFF",
                 "relief": "raised",
                 "frame_relief": "flat",
                 "bg": None,
                 "select_bg": None,
                 "font_main": Font(family="Ubuntu", size=13),
                 "font_users": Font(family="Ubuntu", size=15),
                 "button_font": None,
                 "button_bg": "#A9A9A9",
                 "button_bg_positive": "#2E8B57",
                 "button_bg_negative": "#B22222",
                 "button_bg_active": None,
                 "cursor": None}


def exception_handler(e):
    try:
        print(e)
    except Exception as er:
        print(er)


def request(method, url, req_json=None, files=None, headers=None):
    try:
        return requests.request(method=method, url=url, json=req_json, files=files, headers=headers)
    except Exception as er:
        exception_handler(er)


def response_handler(method, url, req_json=None, files=None, headers=None):
    global access_token, user_login, user_password
    try:
        res = request(method, url, req_json, files, headers)
        if res.status_code == 200:
            return res
        elif res.status_code == 401:
            access_token = check_password(user_login, user_password)
            return request(method, url, req_json, headers={'Authorization': f'Bearer {access_token}'})
        else:
            messagebox.showerror("Something went wrong!", f"Response {res.status_code}")
            return None
    except Exception as er:
        exception_handler(er)


def auto_check_message():
    try:
        get_message()
    except Exception as er:
        exception_handler(er)


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
        return response_handler(method="post", url=f"{backend_url}auth",
                                req_json={"login": log, "password": pas}).json()
    except Exception as er:
        exception_handler(er)


def create_user(lgn, hashed_pass, mail):
    try:
        return response_handler(method="post", url=f"{backend_url}user/create", req_json={'login': lgn,
                                                                                          'password': hashed_pass,
                                                                                          'pubkey': keys_generation(),
                                                                                          'email': mail}).json()
    except Exception as er:
        exception_handler(er)


def get_id(log):
    try:
        return response_handler(method="get", url=f"{backend_url}user/get_id?login={log}").json()
    except Exception as er:
        exception_handler(er)


def find_user(user):
    try:
        return response_handler(method="get", url=f"{backend_url}user/find?login={user}").json()
    except Exception as er:
        exception_handler(er)


def get_user_nickname(user):
    try:
        return response_handler(method="get", url=f"{backend_url}user/get_nickname?id={user}").json()
    except Exception as er:
        exception_handler(er)


def get_random_users():  # дописать
    try:
        return response_handler(method="get", url=f"{backend_url}user/get_random").json()
    except Exception as er:
        exception_handler(er)


def get_pubkey(user):
    try:
        return response_handler(method="get", url=f"{backend_url}user/get_pubkey?id={user}").json()
    except Exception as er:
        exception_handler(er)


def message_send(chat_id, message, message1):
    global user_id, access_token
    try:
        return response_handler(method="post", url=f"{backend_url}message/send",
                                req_json={"sender": user_id, "destination": chat_id,
                                          "message": message, "message1": message1},
                                headers={'Authorization': f'Bearer {access_token}'}).json()
    except Exception as er:
        exception_handler(er)


def message_loop():
    global access_token
    try:
        return response_handler(method="get", url=f"{backend_url}message/loop",
                                headers={'Authorization': f'Bearer {access_token}'}).json()
    except Exception as er:
        exception_handler(er)


def message_send_chat(chat, user, target, message):
    global access_token
    try:
        return response_handler(method="post", url=f"{backend_url}message/send/chat",
                                req_json={"sender": f"{chat}_{user}", "destination": target, "message": message},
                                headers={'Authorization': f'Bearer {access_token}'}).json()
    except Exception as er:
        exception_handler(er)


def doc_send(path, chat):
    global access_token
    try:
        return response_handler(method="get",
                                url=f"{backend_url}url/shorter?url={upload_file(path)}&destination={chat}",
                                headers={'Authorization': f'Bearer {access_token}'}).json()
    except Exception as er:
        exception_handler(er)


def chat_send_doc(path, chat, user, target):
    global access_token
    try:
        return response_handler(method="get",
                                url=f"{backend_url}url/shorter/chat?url={upload_file(path)}&sender={chat}_{user}&"
                                    f"destination={target}", headers={'Authorization': f'Bearer {access_token}'}).json()
    except Exception as er:
        exception_handler(er)


def get_messages(cur_chat, is_chat):
    global access_token
    try:
        try:
            return response_handler(method="get", url=f"{backend_url}message/get?chat_id={cur_chat}&is_chat={is_chat}",
                                    headers={'Authorization': f'Bearer {access_token}'}).json()
        except AttributeError:
            return None
    except Exception as er:
        exception_handler(er)


def regenerate_keys():
    button_regenerate.update()
    global user_login, user_password, access_token
    try:
        res = response_handler(method="put", url=f"{backend_url}user/update_pubkey",
                               req_json={'pubkey': keys_generation()},
                               headers={'Authorization': f'Bearer {access_token}'}).json()
        if res:
            messagebox.showinfo("Success", "Regeneration successful!")
        else:
            messagebox.showerror("Failed", "Regeneration failed!")
    except Exception as er:
        exception_handler(er)


def chat_create(name):
    global access_token
    try:
        return response_handler(method="post", url=f"{backend_url}chat/create", req_json={"name": name},
                                headers={'Authorization': f'Bearer {access_token}'}).json()
    except Exception as er:
        exception_handler(er)


def get_chat_id(name: str):
    try:
        return response_handler(method="get", url=f"{backend_url}chat/get_id?name={name}").json()
    except Exception as er:
        exception_handler(er)


def get_chat_name(group_id: str):
    try:
        return response_handler(method="get", url=f"{backend_url}chat/get_name?group_id={group_id}").json()
    except Exception as er:
        exception_handler(er)


def get_user_groups(user: int):
    try:
        return response_handler(method="get", url=f"{backend_url}user/get_groups?user_id={user}").json()
    except Exception as er:
        exception_handler(er)


def get_chat_users(group_id: str):
    try:
        return response_handler(method="get", url=f"{backend_url}chat/get_users?group_id={group_id}").json()
    except Exception as er:
        exception_handler(er)


def upload_file(path: str):
    try:
        return response_handler(method="post", url=f"{backend_url}file/upload", files={"file": open(path, "rb")}).json()
    except Exception as er:
        exception_handler(er)


def send_recovery(user: str):
    try:
        return response_handler(method="post", url=f"{backend_url}recovery/send?login={user}").json()
    except Exception as er:
        exception_handler(er)


def validate_recovery(local_code: str, lgn: str, hashed_pass=None):
    try:
        return response_handler(method="post", url=f"{backend_url}recovery/validate",
                                req_json={"code": local_code, "login": lgn, "password": hashed_pass}).json()
    except Exception as er:
        exception_handler(er)


def update_password(old_pass: str, new_pass: str):
    global access_token
    try:
        return response_handler(method="put", url=f"{backend_url}user/update_password",
                                req_json={"old_password": old_pass, "new_password": new_pass},
                                headers={'Authorization': f'Bearer {access_token}'}).json()
    except Exception as er:
        exception_handler(er)


def user_invite(name: str, user: int):
    global access_token
    try:
        return response_handler(method="post", url=f"{backend_url}chat/invite", req_json={"name": name, "user": user},
                                headers={'Authorization': f'Bearer {access_token}'}).json()
    except Exception as er:
        exception_handler(er)


def user_kick(name: str, user: int):
    global access_token
    try:
        return response_handler(method="post", url=f"{backend_url}chat/kick", req_json={"name": name, "user": user},
                                headers={'Authorization': f'Bearer {access_token}'}).json()
    except Exception as er:
        exception_handler(er)


# endregion
def auto_login():
    try:
        lgn = keyring.get_password('datachat', 'login')
        psw = keyring.get_password('datachat', 'password')
        if lgn is not None and psw is not None:
            entry_log.insert(0, lgn)
            entry_pass.insert(0, psw)
            remember_var.set(1)
    except Exception as er:
        exception_handler(er)


def clear_auto_login():
    try:
        keyring.delete_password('datachat', 'login')
    except errors.PasswordDeleteError:
        pass
    try:
        keyring.delete_password('datachat', 'password')
    except errors.PasswordDeleteError:
        pass


def fill_auto_login_file(lgn: str, psw: str):
    keyring.set_password('datachat', 'login', lgn)
    keyring.set_password('datachat', 'password', psw)


def login(*args):
    global user_login, user_id, user_password, access_token
    label_loading.place(x=60, y=60)
    button_login.update()
    awake_thread.join()
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
        access_token = res
        if remember_var.get() == 0:
            clear_auto_login()
        else:
            fill_auto_login_file(entry_log.get(), entry_pass.get())
        user_login = entry_log.get()
        user_id = get_id(user_login)
        get_private_key()
        hide_auth_menu()
        label_loading.place_forget()
        try:
            checker.start()
        except NameError:
            pass
        qr = qrcode.make(private_key)
        qr.save(files_dir + '/temp/QR.png')
        qr = Image.open(files_dir + '/temp/QR.png')
        width = int(qr.size[0] / 2)
        height = int(qr.size[1] / 2)
        img = qr.resize((width, height), Image.ANTIALIAS)
        img.save(files_dir + '/temp/QR.png')
        _qr = PhotoImage(file=files_dir + "/temp/QR.png")
        label_qr = Label(main1_frame, image=_qr)
        label_qr.image = _qr
        # label_qr.pack(side=RIGHT, anchor=SE) # задумка на будущее
        os.remove(files_dir + '/temp/QR.png')
        menu_navigation("chat")
    except Exception as e:
        label_loading.place_forget()
        exception_handler(e)


def show_reg_frame():
    root.geometry("200x180+{}+{}".format(w, h))
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
    root.geometry("200x165+{}+{}".format(w, h))
    check_remember.pack(side=TOP, anchor=S)
    button_login.pack(side=LEFT, pady=3, anchor=CENTER)
    button_reg_m.pack(side=RIGHT, pady=3, anchor=CENTER)


def register():
    button_reg.update()
    try:
        lgn, psw = entry_log.get(), entry_pass.get()
        mail = entry_email.get()
        if len(lgn) == 0 or len(psw) == 0:
            messagebox.showerror('Input error', 'Fill all input fields')
            return
        if len(mail) <= 8 or ' ' in mail or '@' not in mail or '.' not in mail:
            messagebox.showerror('Input error', 'Enter valid email')
            return
        if not check_input(psw, lgn):
            return
        hashed_pass = bcrypt.hashpw(psw.encode('utf-8'), bcrypt.gensalt())
        hashed_pass = str(hashed_pass)[2:-1]
        res = create_user(lgn, hashed_pass, mail)
        if res:
            messagebox.showinfo("Success", "Register success!")
        else:
            messagebox.showerror('Input error', 'User already register')
    except Exception as e:
        exception_handler(e)


def hide_auth_menu():
    global w, h
    w -= 200
    auth_frame.pack_forget()
    root.geometry("1000x500+{}+{}".format(w, h))
    entry_msg.focus_set()
    menu_frame.pack(side=LEFT, pady=5, anchor=N)
    main_frame.pack(side=LEFT, anchor=CENTER)


def menu_navigation(menu: str):
    global current_chat, chats, spacing, spacing_2, private_key, user_id, pin_chats
    if menu == "chat":
        button_chat.update()
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
        button_chat.configure(bg=theme['button_bg_positive'])
        button_info.configure(bg=theme['button_bg'])
        button_settings.configure(bg=theme['button_bg'])
        button_groups.configure(bg=theme['button_bg'])
        main1_frame.pack_forget()
        settings_frame.pack_forget()
        group_frame.pack_forget()
        main_frame.pack(side=LEFT, anchor=CENTER)
        canvas.configure(state='normal')
        canvas.delete(0.0, END)
        canvas.configure(state='disable')
        current_chat = "-1"
        label_chat_id.configure(text='Current chat with: ')
        entry_chat_id.delete(0, tk.END)
        spacing, spacing_2 = 0, 0
        button_send2.configure(state='disabled')
        button_img2.configure(state='disabled')
    elif menu == "set":
        button_settings.update()
        button_chat.configure(bg=theme['button_bg'])
        button_info.configure(bg=theme['button_bg'])
        button_settings.configure(bg=theme['button_bg_positive'])
        button_groups.configure(bg=theme['button_bg'])
        main_frame.pack_forget()
        main1_frame.pack_forget()
        group_frame.pack_forget()
        settings_frame.pack(side=LEFT, anchor=N)
    elif menu == "info":
        button_info.update()
        button_chat.configure(bg=theme['button_bg'])
        button_info.configure(bg=theme['button_bg_positive'])
        button_settings.configure(bg=theme['button_bg'])
        button_groups.configure(bg=theme['button_bg'])
        main_frame.pack_forget()
        settings_frame.pack_forget()
        group_frame.pack_forget()
        main1_frame.pack(side=LEFT, anchor=NW)
        users_list = get_random_users()
        for i in canvas_users.get_children():
            canvas_users.delete(i)
        for i in range(users_list['count']):
            try:
                user = users_list[f'user_{i}']
                try:
                    date = str(datetime.strptime(user["last_activity"], "%Y-%m-%dT%H:%M:%S") + utc_diff)[2:]
                except TypeError:
                    date = ""
                canvas_users.insert(parent='', index=END, values=(user['id'], user['login'], date), tags=('bb',))
            except KeyError:
                break
    elif menu == "group":
        button_groups.update()
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
        groups = get_user_groups(int(user_id))
        counter = 0
        for i in groups:
            counter += 1
            chats[i] = tk.Button(menu_frame, text=i, bg=theme['button_bg'], width=17, relief=theme['relief'],
                                 font=theme['button_font'], command=lambda: change_group(
                    get_chat_id(groups[counter - 1]), chats[groups[counter - 1]]))
            if counter % 2 == 0:
                chats[i].pack(side=TOP, pady=5, anchor=N)
            else:
                chats[i].pack(side=TOP, anchor=N)
        group_frame.pack(side=LEFT, anchor=CENTER)
        if counter % 2 == 0:
            button_back.pack(side=TOP, anchor=N)
        else:
            button_back.pack(side=TOP, pady=5, anchor=N)


def change_group(gr_id: str, button):
    global current_chat, chats
    button_send2.configure(state='normal')
    button_img2.configure(state='normal')
    current_chat = gr_id
    for key in chats:
        chats[key].configure(bg=theme['button_bg'])
    button.configure(bg=theme['button_bg_positive'])
    get_chat_message()


def send_message():
    global user_id, current_chat
    button_send.update()
    try:
        msg = entry_msg.get()
        if len(msg) == 0:
            messagebox.showerror('Input error', 'Fill all input fields')
            return
        for i in msg:
            if ord(i) < 32 or ord(i) > 1366:
                messagebox.showerror('Input error', 'Unsupported symbols')
                return
        encrypt_msg = encrypt(msg.encode('utf-8'), get_pubkey(current_chat))
        encrypt_msg1 = encrypt(msg.encode('utf-8'), get_pubkey(user_id))
        message_send(current_chat, encrypt_msg, encrypt_msg1)
        entry_msg.delete(0, tk.END)
        get_message()
    except Exception as e:
        exception_handler(e)


def send_doc():
    button_img.update()
    global current_chat
    try:
        path = filedialog.askopenfilename(filetypes=[("All files", "*.*")])
        if len(path) == 0:
            return
        doc_send(path, current_chat)
        get_message()
    except Exception as e:
        exception_handler(e)


def get_message():
    global user_login, current_chat
    try:
        button_refresh.update()
    except NotImplementedError:
        pass
    res = get_messages(current_chat, 0)
    if res is None:
        return
    cache_messages(res)
    try:
        canvas.configure(state='normal')
        canvas.delete(0.0, END)
        chat_nick = 0
        for i in range(res['count']):
            try:
                message = res[f"item_{i}"]
                if chat_nick == 0 and message["from_id"] != user_login:
                    chat_nick = message["from_id"]
                nick = user_login if message["from_id"] == user_login else chat_nick
                if message['from_id'] == user_login:
                    decrypt_msg = decrypt(int2bytes(message["message1"]))
                else:
                    decrypt_msg = decrypt(int2bytes(message["message"]))
                date = datetime.strptime(message["date"], "%Y-%m-%dT%H:%M:%S")
                content = f'{str(date + utc_diff)[2:]} {nick}: {decrypt_msg}\n'
                canvas.insert(END, content)
                canvas.update()
            except KeyError:
                break
        canvas.configure(state='disabled')
    except Exception as er:
        exception_handler(er)


def encrypt(msg: bytes, pubkey):
    try:
        pubkey = pubkey.split(', ')
        pubkey = rsa.PublicKey(int(pubkey[0]), int(pubkey[1]))
        encrypt_message = rsa.encrypt(msg, pubkey)
        return bytes2int(encrypt_message)
    except Exception as er:
        exception_handler(er)


def decrypt(msg: bytes):
    global private_key
    try:
        decrypted_message = rsa.decrypt(msg, private_key)
        return decrypted_message.decode('utf-8')
    except Exception as er:
        exception_handler(er)
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
        else:
            entry_msg.focus_set()
    elif str(root.focus_get()) == ".!labelframe2.!entry2":
        if len(entry_msg2.get()) != 0:
            send_message()
        else:
            entry_msg2.focus_set()


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
    except Exception as er:
        exception_handler(er)


def get_private_key():
    try:
        global private_key
        private_key = rsa.PrivateKey.load_pkcs1(keyring.get_password('datachat', 'private_key').encode('utf-8'))
    except Exception as er:
        exception_handler(er)


def create_chat():
    global user_id
    button_c_chat.update()
    try:
        name = entry_chat.get()
        if len(name) < 5:
            messagebox.showerror("Input error", "Name length must be more than 5 characters")
            return
        if name[-3:] != '_gr':
            messagebox.showerror("Input error", "Name must contain '_gr' in the end")
            return
        for i in name:
            if ord(i) < 45 or ord(i) > 122:
                messagebox.showerror('Input error', 'Unsupported symbols')
                return
        res = chat_create(name)
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
    button_send2.update()
    message = entry_msg2.get()
    try:
        if len(message) == 0:
            messagebox.showerror('Input error', 'Fill all input fields')
            return
        for i in get_chat_users(current_chat):
            message_send_chat(current_chat, user_id, i[0], encrypt(message.encode('utf-8'), get_pubkey(i[0])))
            entry_msg2.delete(0, tk.END)
        get_chat_message()
    except Exception as e:
        exception_handler(e)


def send_chat_doc():
    global user_id, current_chat
    button_img2.update()
    try:
        path = filedialog.askopenfilename(filetypes=[("All files", "*.*")])
        if len(path) == 0:
            return
        for i in get_chat_users(current_chat):
            chat_send_doc(path, current_chat, user_id, i[0])
        get_chat_message()
    except Exception as e:
        exception_handler(e)


def get_chat_message():
    global current_chat
    try:
        button_refresh2.update()
    except NotImplementedError:
        pass
    res = get_messages(current_chat, 1)
    if res is None:
        return
    cache_messages(res)
    try:
        canvas_2.configure(state='normal')
        canvas_2.delete(0.0, END)
        for i in range(res['count']):
            try:
                message = res[f"item_{i}"]
                decrypt_msg = decrypt(int2bytes(message["message"]))
                date = datetime.strptime(message["date"], "%Y-%m-%dT%H:%M:%S")
                content = f'{str(date + utc_diff)[2:]} {message["from_id"]}: {decrypt_msg}\n'
                canvas_2.insert(END, content)
                canvas_2.update()
            except KeyError:
                break
        canvas_2.configure(state='disabled')
    except Exception as e:
        exception_handler(e)


def invite_to_group():
    global user_id
    button_invite.update()
    inv_user = entry_inv_id.get()
    inv_group = entry_gr_toinv.get()
    if len(inv_user) == 0 and len(inv_group) == 0:
        messagebox.showerror('Input error', 'Entries length must be more than 0 characters')
        return
    try:
        name = get_chat_name(inv_group)
        groups = get_user_groups(inv_user)
        if name in groups:
            messagebox.showerror('Input error', "Пользователь уже состоит в группе")
            return
        if not user_invite(name, int(inv_user)):
            messagebox.showerror('Access error', "You are not chat's owner")
            return
        messagebox.showinfo('Success', "Success")
    except Exception as e:
        exception_handler(e)


def kick_from_group():
    global user_id
    button_kick.update()
    kick_user = entry_kick_id.get()
    kick_group = entry_gr_tokick.get()
    if len(kick_user) == 0 and len(kick_group) == 0:
        messagebox.showerror('Input error', 'Entries lenght must be more than 0 characters')
        return
    try:
        name = get_chat_name(kick_group)
        groups = get_user_groups(kick_user)
        if name not in groups:
            messagebox.showerror('Input error', "User is not in group")
            return
        if not user_kick(name, int(kick_user)):
            messagebox.showerror('Access error', "You are not chat's owner")
            return
        messagebox.showinfo('Success', "Success")
    except Exception as e:
        exception_handler(e)


def logout():
    global w, h
    w += 200
    menu_navigation("chat")
    menu_frame.pack_forget()
    main_frame.pack_forget()
    root.geometry("200x165+{}+{}".format(w, h))
    entry_log.focus_set()
    auth_frame.pack(side=TOP, anchor=CENTER)


def recovery_menu():
    global w, h, code
    try:
        auth_frame.pack_forget()
        root.geometry("200x100+{}+{}".format(w, h))
        recovery_frame.pack(side=TOP, anchor=CENTER)
    except Exception as er:
        exception_handler(er)


def new_pass_menu():
    global w, h, user_login, code
    try:
        code = entry_code.get()
        if not validate_recovery(entry_code.get(), entry_log.get()):
            messagebox.showerror('Input error', 'Incorrect code')
            return
        recovery_frame.pack_forget()
        root.geometry("200x130+{}+{}".format(w, h))
        new_pass_frame.pack(side=TOP, anchor=CENTER)
    except Exception as er:
        exception_handler(er)


def change_password():
    global user_login
    button_pass_font.update()
    try:
        hashed_pass = bcrypt.hashpw(entry_new_pass.get().encode('utf-8'), bcrypt.gensalt())
        hashed_pass = str(hashed_pass)[2:-1]
        res = update_password(entry_old_pass.get(), hashed_pass)
        if res:
            messagebox.showinfo("Success", "Password has been changed")
            fill_auto_login_file(user_login, entry_new_pass.get())
            return
        elif res is None:
            messagebox.showerror('Input error', 'User not found')
            return
        else:
            messagebox.showerror("Input error", "Current password is wrong")
    except Exception as e:
        exception_handler(e)


def set_new_pass():
    global user_login, email, code
    button_code.update()
    user_login = entry_log.get()
    try:
        if check_input(entry_new_p2.get(), entry_new_p.get()):
            if entry_new_p.get() == entry_new_p2.get():
                hashed_pass = bcrypt.hashpw(entry_new_p.get().encode('utf-8'), bcrypt.gensalt())
                hashed_pass = str(hashed_pass)[2:-1]
                res = validate_recovery(code, user_login, hashed_pass)
                if res:
                    messagebox.showinfo("Success", "Password has been changed")
                    fill_auto_login_file(user_login, entry_new_p.get())
                    entry_pass.delete(0, tk.END)
                    entry_pass.insert(0, entry_new_p.get())
                    root.geometry("200x160+{}+{}".format(w, h))
                    new_pass_frame.pack_forget()
                    auth_frame.pack(side=TOP, anchor=CENTER)
                else:
                    messagebox.showerror("Failed", "Password has not been changed")
    except Exception as er:
        exception_handler(er)


def pass_code():
    try:
        res = send_recovery(entry_log.get())
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
    button_chat_id.update()
    if len(chat_id) == 0 or not chat_id.isnumeric():
        messagebox.showerror('Input error', 'Chat id must be a number')
        return
    nick = get_user_nickname(int(chat_id))
    if nick is not None:
        label_chat_id.configure(text='Current chat with: ' + nick)
    else:
        messagebox.showerror('Input error', 'User not found')
        return
    current_chat = chat_id
    button_send.configure(state='normal')
    button_img.configure(state='normal')
    canvas.configure(state='normal')
    canvas.delete(0.0, END)
    canvas.configure(state='disable')
    get_message()


def search_user():
    try:
        res = entry_user_search.get()
        if len(res) == 0:
            return
        users_list = find_user(res)
        for i in canvas_users.get_children():
            canvas_users.delete(i)
        for i in range(users_list['count']):
            try:
                user = users_list[f'user_{i}']
                try:
                    date = str(datetime.strptime(user["last_activity"], "%Y-%m-%dT%H:%M:%S") + utc_diff)[2:]
                except TypeError:
                    date = ""
                canvas_users.insert(parent='', index=END, values=(user['id'], user['login'], date), tags=('bb',))
            except KeyError:
                break
    except Exception as e:
        exception_handler(e)


def cache_messages(messages):
    global current_chat
    try:
        with open(files_dir + "\\cache\\" + current_chat) as file:
            json.load(file)
    except FileNotFoundError:
        pass
    except Exception as e:
        exception_handler(e)


def pin_chat():
    try:
        user = entry_pin.get()
        if len(user) == 0:
            messagebox.showerror('Input error', 'Empty input')
            return
        name = get_user_nickname(user)
        if name is None:
            messagebox.showerror('Input error', 'User not found')
            return
        info = user + ' ' + name
        with open(files_dir + "/settings/config.json", "r") as file:
            json_file = json.load(file)
        pin1 = json_file['pin1']
        if pin1 is None:
            json_file['pin1'] = info
            with open(files_dir + "/settings/config.json", "w") as file:
                json.dump(json_file, file, indent=2)
            return
        pin2 = json_file['pin2']
        if pin2 is None:
            json_file['pin2'] = info
            with open(files_dir + "/settings/config.json", "w") as file:
                json.dump(json_file, file, indent=2)
            return
        pin3 = json_file['pin3']
        if pin3 is None:
            json_file['pin3'] = info
            with open(files_dir + "/settings/config.json", "w") as file:
                json.dump(json_file, file, indent=2)
            return
        messagebox.showerror('Pin error', 'Pin limit')
    except Exception as e:
        exception_handler(e)


def unpin_chat(l_frame, id: int):
    try:
        pin_chats.remove(l_frame)
        l_frame.pack_forget()
        with open(files_dir + "/settings/config.json", "r") as file:
            json_file = json.load(file)
        if id == 1:
            json_file['pin1'] = json_file['pin2']
            json_file['pin2'] = json_file['pin3']
            json_file['pin3'] = None
        elif id == 2:
            json_file['pin2'] = json_file['pin3']
            json_file['pin3'] = None
        else:
            json_file['pin3'] = None
        with open(files_dir + "/settings/config.json", "w") as file:
            json.dump(json_file, file, indent=2)
    except Exception as er:
        exception_handler(er)


def pin_constructor(text: str, chat: str, id: int):
    try:
        local_frame = tk.LabelFrame(menu_frame, width=150, height=50, relief=FLAT, bg=theme['bg'])
        button1 = tk.Button(local_frame, text=text, activebackground=theme['button_bg_active'], bg=theme['button_bg'],
                            width=13, relief=theme['relief'], font=theme['button_font'],
                            command=lambda: (menu_navigation("chat"), open_chat(chat)))
        button2 = tk.Button(local_frame, text='-', activebackground=theme['button_bg_active'], width=2,
                            font=theme['button_font'], bg=theme['button_bg_negative'], relief=theme['relief'],
                            command=lambda: unpin_chat(local_frame, id))
        button1.pack(side=LEFT, anchor=N)
        button2.pack(side=LEFT, anchor=N, padx=3)
        local_frame.pack(side=TOP, anchor=N)
        pin_chats.append(local_frame)
    except Exception as er:
        exception_handler(er)


def get_pin_chats():
    global pin_chats
    try:
        with open(files_dir + "/settings/config.json", "r") as file:
            json_file = json.load(file)
        for i in range(3):
            pin = json_file[f'pin{i + 1}']
            if pin is None:
                if i == 0:
                    label_fixed.pack_forget()
                    label_line1.pack_forget()
                    label_line2.pack_forget()
                    return
            pin = pin.split()
            pin_constructor(pin[1], pin[0], i + 1)
    except Exception as er:
        exception_handler(er)


def save_theme():
    global theme_var
    with open(files_dir + "/settings/config.json", "r") as file:
        json_file = json.load(file)
    json_file['theme'] = theme_var.get()
    with open(files_dir + "/settings/config.json", "w") as file:
        json.dump(json_file, file, indent=2)
    if theme_var.get() == 2:
        if not os.path.exists(files_dir + "/settings/theme.json"):
            create_theme_file()
        theme_editor()
    else:
        messagebox.showinfo("Success!", "Theme will be changed on next launch!")


def theme_editor():
    global relief, frames_relief, cursors
    with open(files_dir + "/settings/theme.json", "r") as file:
        temp = json.load(file)
    relief.set(temp['relief'])
    frames_relief.set(temp['frame_relief'])
    cursors.set(temp['cursor'])
    theme_editor_window.deiconify()
    entry_text.insert(0, temp['text_color'])
    entry_entry.insert(0, temp['entry'])
    entry_bg.insert(0, temp['bg'])
    entry_sel_bg.insert(0, temp['select_bg'])
    entry_font.insert(0, temp['font_main'])
    entry_font_u.insert(0, temp['font_users'])
    entry_font_b.insert(0, temp['button_font'])
    entry_bg_b.insert(0, temp['button_bg'])
    entry_bg_b_pos.insert(0, temp['button_bg_positive'])
    entry_bg_b_neg.insert(0, temp['button_bg_negative'])
    entry_b_act.insert(0, temp['button_bg_active'])


def theme_editor_save():
    theme_dict = {}
    theme_dict.update({"text_color": entry_text.get(),
                       "entry": entry_entry.get(),
                       "relief": relief.get(),
                       "frame_relief": frames_relief.get(),
                       "bg": entry_bg.get(),
                       "select_bg": entry_sel_bg.get(),
                       "font_main": entry_font.get(),
                       "font_users": entry_font_u.get(),
                       "button_font": entry_font_b.get(),
                       "button_bg": entry_bg_b.get(),
                       "button_bg_positive": entry_bg_b_pos.get(),
                       "button_bg_negative": entry_bg_b_neg.get(),
                       "button_bg_active": entry_b_act.get(),
                       "cursor": cursors.get()})
    with open(files_dir + "/settings/theme.json", "w") as file:
        json.dump(theme_dict, file, indent=2)
    messagebox.showinfo("Success!", "Theme will be changed on next launch!")


def export_program_data():
    global user_password
    try:
        files, paths = [], []
        destination = filedialog.askdirectory()
        with open(files_dir + "\\settings\\key.json", "w") as file:
            json.dump({"key": keyring.get_password("datachat", "private_key")}, file)
        for i in os.listdir(files_dir + "\\settings"):
            files.append(files_dir + "\\settings\\" + i)
        for i in os.listdir(files_dir + "\\cache"):
            files.append(files_dir + "\\cache\\" + i)
        for i in range(len(files)):
            paths.append("\\")
        pyminizip.compress_multiple(files, paths, destination + "\\export.zip", user_password, 3)
        os.remove(files_dir + "\\settings\\key.json")
    except Exception as e:
        exception_handler(e)


def import_program_data():
    try:
        path = filedialog.askopenfilename(filetypes=[("Zip files", "*.zip")])
        pyminizip.uncompress(path, user_password, files_dir + "\\temp", 0)
        with open(files_dir + "\\temp\\key.json", "r") as file:
            key = json.load(file)["key"]
        keyring.set_password("datachat", "private_key", key)
        os.replace(files_dir + "\\temp\\theme.json", files_dir + "\\settings\\theme.json")
        os.replace(files_dir + "\\temp\\config.json", files_dir + "\\settings\\config.json")
        os.remove(files_dir + "\\temp\\key.json")
        for i in os.listdir(files_dir + "\\temp"):
            os.replace(files_dir + "\\temp\\" + i, files_dir + "\\cache\\" + i)
    except Exception as e:
        exception_handler(e)


def open_link(*args):
    try:
        print(canvas.selection_get())
    except tk.TclError:
        pass


def get_update_time():
    global time_to_check
    with open(files_dir + "/settings/config.json", "r") as file:
        time_to_check = json.load(file)['update']
    if int(time_to_check) == -1:
        label_check2.configure(text="Never")
    else:
        label_check2.configure(text=f"{time_to_check} Sec")
    label_check2.update()


def auto_check():
    global time_to_check
    time_to_check = int(time_to_check) + 15
    if time_to_check < 15:
        time_to_check = 15
        label_check2.configure(text="15 Sec")
    elif time_to_check > 60:
        time_to_check = -1
        label_check2.configure(text="Never")
    else:
        label_check2.configure(text=f"{time_to_check} Sec")
    label_check2.update()
    messagebox.showinfo('Success!', 'Notifications will be changed on next launch!')
    with open(files_dir + "/settings/config.json", "r") as file:
        json_file = json.load(file)
    json_file['update'] = str(time_to_check)
    with open(files_dir + "/settings/config.json", "w") as file:
        json.dump(json_file, file, indent=2)


def loop_msg_func():
    global time_to_check
    print('check')
    try:
        if access_token == '':
            return
        res = message_loop()
        if res is not None:
            messagebox.showinfo('New messages!', 'You have new messages in chats: ' + res)
        if current_chat != '-1':
            if current_chat[0] != 'g':
                get_message()
            elif current_chat[0] == 'g':
                get_chat_message()
        sch.enter(int(time_to_check), 1, loop_msg_func)
    except Exception as e:
        exception_handler(e)


def loop_get_msg():
    sch.run()


def api_awake():
    requests.head(f"{backend_url}api/awake")


folders()
awake_thread = threading.Thread(target=api_awake, daemon=True)
awake_thread.start()
set_theme()
"""m = Menu(root)
root.config(menu=m)
fm = Menu(m)
m.add_cascade(label="File", menu=fm)
fmm = Menu(fm)
fm.add_cascade(label="Export", menu=fmm)"""
# region auth
auth_frame = LabelFrame(root, width=200, height=130, relief=FLAT, bg=theme['bg'])
auth_frame.pack(side=TOP, anchor=CENTER)
label_user = tk.Label(auth_frame, font=theme['font_main'], text="Username:", bg=theme['bg'],
                      fg=theme['text_color'], width=19, anchor=W)
label_user.pack(side=TOP, anchor=S)
entry_log = tk.Entry(auth_frame, font=12, width=20, fg=theme['text_color'], bg=theme['entry'], relief=theme['relief'],
                     cursor=theme['cursor'])
entry_log.bind("<Return>", login_handler)
entry_log.pack(side=TOP)
label_password = tk.Label(auth_frame, font=theme['font_main'], text="Password:", bg=theme['bg'],
                          fg=theme['text_color'], width=19, anchor=W)
label_password.pack(side=TOP, anchor=S)
entry_pass = tk.Entry(auth_frame, font=12, width=20, fg=theme['text_color'], bg=theme['entry'], relief=theme['relief'],
                      cursor=theme['cursor'], show='•')
entry_pass.bind("<Return>", login)
entry_pass.pack(side=TOP)
check_remember = tk.Checkbutton(auth_frame, font=theme['font_main'], fg=theme['text_color'], bg=theme['bg'],
                                text='Remember me', activebackground=theme['bg'], selectcolor=theme['bg'],
                                variable=remember_var)
check_remember.pack(side=TOP, anchor=S)
button_login = tk.Button(auth_frame, text="LOGIN", activebackground=theme['button_bg_active'], relief=theme['relief'],
                         bg=theme['button_bg_positive'], width=11, command=lambda: login(), font=theme['button_font'])
button_login.pack(side=LEFT, pady=3, anchor=CENTER)
button_reg_m = tk.Button(auth_frame, text="REGISTER", activebackground=theme['button_bg_active'],
                         relief=theme['relief'],
                         bg=theme['button_bg_positive'], width=11, command=lambda: show_reg_frame(),
                         font=theme['button_font'])
button_reg_m.pack(side=RIGHT, pady=3, anchor=CENTER)
button_reg = tk.Button(auth_frame, text="REGISTER", activebackground=theme['button_bg_active'], relief=theme['relief'],
                       bg=theme['button_bg_positive'], width=11, command=lambda: register(), font=theme['button_font'])
button_login_b = tk.Button(auth_frame, text="BACK", activebackground=theme['button_bg_active'], relief=theme['relief'],
                           bg=theme['button_bg_positive'], width=11, command=lambda: back_to_login(),
                           font=theme['button_font'])
# endregion
# region reg
recovery_frame = LabelFrame(root, width=200, height=130, relief=FLAT, bg=theme['bg'])
label_code = tk.Label(recovery_frame, font=theme['font_main'], text="Code:", fg=theme['text_color'], bg=theme['bg'],
                      width=19, anchor=W)
label_code.pack(side=TOP, anchor=S)
entry_code = tk.Entry(recovery_frame, font=12, width=20, fg=theme['text_color'], bg=theme['entry'],
                      relief=theme['relief'], cursor=theme['cursor'])
entry_code.pack(side=TOP)
button_code = tk.Button(recovery_frame, text="SEND", activebackground=theme['button_bg_active'], relief=theme['relief'],
                        bg=theme['button_bg_positive'], width=11, command=lambda: new_pass_menu(),
                        font=theme['button_font'])
button_code.pack(side=RIGHT, pady=3, anchor=CENTER)
# endregion
# region new pass
new_pass_frame = LabelFrame(root, width=200, height=130, relief=FLAT, bg=theme['bg'])
label_code = tk.Label(new_pass_frame, font=theme['font_main'], text="New Password:", fg=theme['text_color'],
                      bg=theme['bg'], width=19, anchor=W)
label_code.pack(side=TOP, anchor=S)
entry_new_p = tk.Entry(new_pass_frame, font=12, width=20, fg=theme['text_color'], bg=theme['entry'],
                       cursor=theme['cursor'], show='•')
entry_new_p.pack(side=TOP)
label_code2 = tk.Label(new_pass_frame, font=theme['font_main'], text="Repeat Password:", fg=theme['text_color'],
                       bg=theme['bg'], width=19, anchor=W)
label_code2.pack(side=TOP, anchor=S)
entry_new_p2 = tk.Entry(new_pass_frame, font=12, width=20, fg=theme['text_color'], bg=theme['entry'],
                        cursor=theme['cursor'], show='•')
entry_new_p2.pack(side=TOP)
button_code = tk.Button(new_pass_frame, text="SET", activebackground=theme['button_bg_active'], relief=theme['relief'],
                        bg=theme['button_bg_positive'], width=11, command=lambda: set_new_pass(),
                        font=theme['button_font'])
button_code.pack(side=RIGHT, pady=3, anchor=CENTER)
# endregion
# region email
label_email = tk.Label(auth_frame, font=theme['font_main'], text="Email:", fg=theme['text_color'], bg=theme['bg'],
                       width=19, anchor=W)
entry_email = tk.Entry(auth_frame, font=12, width=20, fg=theme['text_color'], bg=theme['entry'], relief=theme['relief'],
                       cursor=theme['cursor'])
# endregion
# region main menu
main_frame = LabelFrame(root, width=850, height=500, bg=theme['bg'], relief=theme['relief'])
group_frame = LabelFrame(root, width=850, height=500, bg=theme['bg'], relief=theme['relief'])
settings_frame = LabelFrame(root, width=600, height=500, bg=theme['bg'], relief=theme['frame_relief'])
menu_frame = LabelFrame(root, width=150, height=500, relief=FLAT, bg=theme['bg'])
button_chat = tk.Button(menu_frame, text="CHAT", activebackground=theme['button_bg_active'], relief=theme['relief'],
                        bg=theme['button_bg_positive'], width=17, command=lambda: menu_navigation("chat"),
                        font=theme['button_font'])
button_chat.pack(side=TOP, anchor=N)
button_info = tk.Button(menu_frame, text="INFO", activebackground=theme['button_bg_active'], bg=theme['button_bg'],
                        width=17, relief=theme['relief'], command=lambda: menu_navigation("info"),
                        font=theme['button_font'])
button_info.pack(side=TOP, pady=5, anchor=N)
button_settings = tk.Button(menu_frame, text="SETTINGS", activebackground=theme['button_bg_active'], width=17,
                            bg=theme['button_bg'], relief=theme['relief'],
                            command=lambda: menu_navigation("set"), font=theme['button_font'])
button_settings.pack(side=TOP, anchor=N)
button_groups = tk.Button(menu_frame, text="GROUPS", activebackground=theme['button_bg_active'], bg=theme['button_bg'],
                          width=17, relief=theme['relief'], command=lambda: menu_navigation("group"),
                          font=theme['button_font'])
button_groups.pack(side=TOP, pady=5, anchor=N)
label_line1 = tk.Label(menu_frame, font=theme['font_main'], text="-" * 20, fg=theme['text_color'], bg=theme['bg'])
label_line1.pack(side=TOP, anchor=N)
label_fixed = tk.Label(menu_frame, font=theme['font_main'], text="PIN CHATS", fg=theme['text_color'], bg=theme['bg'])
label_fixed.pack(side=TOP, anchor=N)
get_pin_chats()
label_line2 = tk.Label(menu_frame, font=theme['font_main'], text="-" * 20, fg=theme['text_color'], bg=theme['bg'])
label_line2.pack(side=TOP, anchor=N)
button_logout = tk.Button(menu_frame, text="LOGOUT", activebackground=theme['button_bg_active'],
                          bg=theme['button_bg_negative'], width=17, relief=theme['relief'], font=theme['button_font'],
                          command=lambda: logout())
button_logout.pack(side=BOTTOM, pady=5, anchor=N)
button_back = tk.Button(menu_frame, text="BACK", activebackground=theme['button_bg_active'],
                        bg=theme['button_bg_negative'], width=17, relief=theme['relief'], font=theme['button_font'],
                        command=lambda: menu_navigation("chat"))
main2_frame = LabelFrame(main_frame, width=600, height=350, relief=FLAT, bg=theme['bg'])
main2_frame.pack(side=TOP, anchor=CENTER)
main2_frame2 = LabelFrame(group_frame, width=600, height=350, relief=FLAT, bg=theme['bg'])
main2_frame2.pack(side=TOP, anchor=CENTER)
# endregion
# region chat
chat_frame = LabelFrame(main2_frame, width=600, height=25, relief=FLAT, bg=theme['bg'])
chat_frame.pack(side=TOP, pady=2, anchor=N)
label_chat_id = tk.Label(chat_frame, font=theme['font_main'], text="Current chat with: ", fg=theme['text_color'],
                         bg=theme['bg'], width=25, anchor=W)
label_chat_id.pack(side=LEFT, anchor=W)
entry_chat_id = tk.Entry(chat_frame, font=12, width=20, fg=theme['text_color'], bg=theme['entry'],
                         relief=theme['relief'], cursor=theme['cursor'])
entry_chat_id.pack(side=LEFT, padx=165, anchor=CENTER)
button_chat_id = tk.Button(chat_frame, text="OPEN", activebackground=theme['button_bg_active'], relief=theme['relief'],
                           bg=theme['button_bg_positive'], width=15, command=lambda: open_chat(entry_chat_id.get()))
button_chat_id.pack(side=RIGHT, anchor=E)

frame = Frame(main2_frame, width=850, height=450)
frame.pack()
canvas = Text(frame, fg=theme['text_color'], bg=theme['entry'], width=105, cursor='arrow')
scroll = Scrollbar(frame, command=canvas.yview, bg=theme['bg'])
scroll.pack(side=RIGHT, fill=Y)
canvas.pack(side=RIGHT, expand=True, fill=BOTH)
canvas.config(yscrollcommand=scroll.set)
canvas.configure(state='disabled')
canvas.bind("<ButtonRelease>", open_link)
frame_2 = Frame(main2_frame2, width=850, height=500)
frame_2.pack()
canvas_2 = Text(frame_2, fg=theme['text_color'], bg=theme['entry'], width=105, height=27, cursor='arrow')
scroll_2 = Scrollbar(frame_2, command=canvas_2.yview, bg=theme['bg'])
scroll_2.pack(side=RIGHT, fill=Y)
canvas_2.pack(side=RIGHT, expand=True, fill=BOTH)
canvas_2.config(yscrollcommand=scroll_2.set)
canvas_2.configure(state='disabled')

button_refresh = tk.Button(main_frame, text="REFRESH", activebackground=theme['button_bg_active'], width=120,
                           bg=theme['button_bg_positive'], relief=theme['relief'], command=lambda: get_message())
button_refresh.pack(side=TOP, pady=3, anchor=CENTER)
entry_msg = tk.Entry(main_frame, font=10, width=85, relief=theme['relief'], fg=theme['text_color'], bg=theme['entry'],
                     cursor=theme['cursor'])
entry_msg.bind("<Return>", send_message_handler)
entry_msg.pack(side=LEFT, padx=3)
button_img = tk.Button(main_frame, text="➕", activebackground=theme['button_bg_active'], bg=theme['button_bg_positive'],
                       width=3, relief=theme['relief'], command=lambda: send_doc(), state='disabled')
button_img.pack(side=LEFT, anchor=E)
button_send = tk.Button(main_frame, text="SEND", activebackground=theme['button_bg_active'], relief=theme['relief'],
                        bg=theme['button_bg_positive'], width=8, command=lambda: send_message(), state='disabled')
button_send.pack(side=LEFT, anchor=E, padx=3)

button_refresh2 = tk.Button(group_frame, text="REFRESH", activebackground=theme['button_bg_active'], width=121,
                            bg=theme['button_bg_positive'], relief=theme['relief'], command=lambda: get_chat_message())
button_refresh2.pack(side=TOP, pady=3, anchor=CENTER)
entry_msg2 = tk.Entry(group_frame, font=10, width=85, relief=theme['relief'], fg=theme['text_color'], bg=theme['entry'],
                      cursor=theme['cursor'])
# entry_msg2.bind("<Return>", send_chat_message())
entry_msg2.pack(side=LEFT, padx=3)
button_img2 = tk.Button(group_frame, text="➕", activebackground=theme['button_bg_active'], relief=theme['relief'],
                        bg=theme['button_bg_positive'], width=3, state='disabled', command=lambda: send_chat_doc())
button_img2.pack(side=LEFT, anchor=E)
button_send2 = tk.Button(group_frame, text="SEND", activebackground=theme['button_bg_active'], relief=theme['relief'],
                         bg=theme['button_bg_positive'], width=8, state='disabled', command=lambda: send_chat_message())
button_send2.pack(side=LEFT, anchor=E, padx=3)
entry_log.focus_set()
# root.after(500, loop)
# endregion
# region settings
settings_frame_2 = LabelFrame(settings_frame, width=600, height=25, relief=FLAT, bg=theme['bg'])
settings_frame_2.pack(side=TOP, pady=2, anchor=N)
label_check = tk.Label(settings_frame_2, font=10, text="  Update frequency:", fg=theme['text_color'], bg=theme['bg'],
                       width=18, anchor=W)
label_check.pack(side=LEFT, anchor=W)
label_check2 = tk.Label(settings_frame_2, font=12, text='1 min', width=20, fg=theme['text_color'], bg=theme['bg'])
label_check2.pack(side=LEFT, padx=170, anchor=CENTER)
button_check_msg = tk.Button(settings_frame_2, text="UPDATE", activebackground=theme['button_bg_active'], width=15,
                             bg=theme['button_bg_positive'], relief=theme['relief'], command=lambda: auto_check())
button_check_msg.pack(side=RIGHT, anchor=E)

settings_frame7 = LabelFrame(settings_frame, width=600, height=25, relief=FLAT, bg=theme['bg'])
settings_frame7.pack(side=TOP, pady=2, anchor=N)
label_chat = tk.Label(settings_frame7, font=10, text="  Create chat:", fg=theme['text_color'], bg=theme['bg'], width=18,
                      anchor=W)
label_chat.pack(side=LEFT, anchor=W)
entry_chat = tk.Entry(settings_frame7, font=12, width=20, fg=theme['text_color'], bg=theme['entry'],
                      cursor=theme['cursor'], relief=theme['relief'])
entry_chat.pack(side=LEFT, padx=170, anchor=CENTER)
button_c_chat = tk.Button(settings_frame7, text="CREATE", activebackground=theme['button_bg_active'], width=15,
                          bg=theme['button_bg_positive'], relief=theme['relief'], command=lambda: create_chat())
button_c_chat.pack(side=RIGHT, anchor=E)

settings_frame11 = LabelFrame(settings_frame, width=600, height=25, relief=FLAT, bg=theme['bg'])
settings_frame11.pack(side=TOP, pady=2, anchor=N)
label_pin = tk.Label(settings_frame11, font=10, text="  Pin chat:", fg=theme['text_color'], bg=theme['bg'], width=18,
                     anchor=W)
label_pin.pack(side=LEFT, anchor=W)
entry_pin = tk.Entry(settings_frame11, font=12, width=20, fg=theme['text_color'], bg=theme['entry'],
                     cursor=theme['cursor'], relief=theme['relief'])
entry_pin.pack(side=LEFT, padx=170, anchor=CENTER)
button_pin = tk.Button(settings_frame11, text="PIN", activebackground=theme['button_bg_active'], width=15,
                       bg=theme['button_bg_positive'], relief=theme['relief'], command=lambda: pin_chat())
button_pin.pack(side=RIGHT, anchor=E)

settings_frame8 = LabelFrame(settings_frame, width=600, height=25, relief=FLAT, bg=theme['bg'])
settings_frame8.pack(side=TOP, pady=2, anchor=N)
settings_frame9 = LabelFrame(settings_frame8, width=600, height=25, relief=FLAT, bg=theme['bg'])
settings_frame9.pack(side=LEFT, pady=2, anchor=N)
label_inv_id = tk.Label(settings_frame9, font=10, text="  ID to invite:", fg=theme['text_color'], bg=theme['bg'],
                        width=18, anchor=W)
label_inv_id.pack(side=TOP, anchor=W)
entry_inv_id = tk.Entry(settings_frame9, font=12, width=20, fg=theme['text_color'], bg=theme['entry'],
                        cursor=theme['cursor'], relief=theme['relief'])
entry_inv_id.pack(side=TOP, anchor=CENTER)
settings_frame10 = LabelFrame(settings_frame8, width=600, height=25, relief=FLAT, bg=theme['bg'])
settings_frame10.pack(side=LEFT, pady=2, padx=158, anchor=N)
label_gr_toinv = tk.Label(settings_frame10, font=10, text="Group id:", fg=theme['text_color'], bg=theme['bg'], width=18,
                          anchor=W)
label_gr_toinv.pack(side=TOP, anchor=W)
entry_gr_toinv = tk.Entry(settings_frame10, font=12, width=20, fg=theme['text_color'], bg=theme['entry'],
                          cursor=theme['cursor'], relief=theme['relief'])
entry_gr_toinv.pack(side=TOP, anchor=CENTER)
button_invite = tk.Button(settings_frame8, text="INVITE", activebackground=theme['button_bg_active'], width=15,
                          bg=theme['button_bg_positive'], relief=theme['relief'], command=lambda: invite_to_group())
button_invite.pack(side=RIGHT, anchor=S)

settings_frame20 = LabelFrame(settings_frame, width=600, height=25, relief=FLAT, bg=theme['bg'])
settings_frame20.pack(side=TOP, pady=2, anchor=N)
settings_frame21 = LabelFrame(settings_frame20, width=600, height=25, relief=FLAT, bg=theme['bg'])
settings_frame21.pack(side=LEFT, pady=2, anchor=N)
label_kick_id = tk.Label(settings_frame21, font=10, text="  ID to kick:", fg=theme['text_color'], bg=theme['bg'],
                         width=18, anchor=W)
label_kick_id.pack(side=TOP, anchor=W)
entry_kick_id = tk.Entry(settings_frame21, font=12, width=20, fg=theme['text_color'], bg=theme['entry'],
                         cursor=theme['cursor'], relief=theme['relief'])
entry_kick_id.pack(side=TOP, anchor=CENTER)
settings_frame10 = LabelFrame(settings_frame20, width=600, height=25, relief=FLAT, bg=theme['bg'])
settings_frame10.pack(side=LEFT, pady=2, padx=158, anchor=N)
label_gr_tokick = tk.Label(settings_frame10, font=10, text="Group id:", fg=theme['text_color'], bg=theme['bg'],
                           width=18, anchor=W)
label_gr_tokick.pack(side=TOP, anchor=W)
entry_gr_tokick = tk.Entry(settings_frame10, font=12, width=20, fg=theme['text_color'], bg=theme['entry'],
                           cursor=theme['cursor'], relief=theme['relief'])
entry_gr_tokick.pack(side=TOP, anchor=CENTER)
button_kick = tk.Button(settings_frame20, text="KICK", activebackground=theme['button_bg_active'], width=15,
                        bg=theme['button_bg_positive'], relief=theme['relief'], command=lambda: kick_from_group())
button_kick.pack(side=RIGHT, anchor=S)

settings_frame3 = LabelFrame(settings_frame, width=600, height=25, relief=FLAT, bg=theme['bg'])
settings_frame3.pack(side=TOP, pady=2, anchor=N)
settings_frame5 = LabelFrame(settings_frame3, width=600, height=25, relief=FLAT, bg=theme['bg'])
settings_frame5.pack(side=LEFT, pady=2, anchor=N)
label_old_pass = tk.Label(settings_frame5, font=10, text="  Current password:", fg=theme['text_color'],
                          bg=theme['bg'], width=18, anchor=W)
label_old_pass.pack(side=TOP, anchor=W)
entry_old_pass = tk.Entry(settings_frame5, font=12, width=20, fg=theme['text_color'], bg=theme['entry'],
                          cursor=theme['cursor'], relief=theme['relief'], show='•')
entry_old_pass.bind("<Return>", change_pass_handler)
entry_old_pass.pack(side=TOP, anchor=CENTER)
settings_frame6 = LabelFrame(settings_frame3, width=600, height=25, relief=FLAT, bg=theme['bg'])
settings_frame6.pack(side=LEFT, pady=2, padx=158, anchor=N)
label_new_pass = tk.Label(settings_frame6, font=10, text="New password:", fg=theme['text_color'], bg=theme['bg'],
                          width=18, anchor=W)
label_new_pass.pack(side=TOP, anchor=W)
entry_new_pass = tk.Entry(settings_frame6, font=12, width=20, fg=theme['text_color'], bg=theme['entry'],
                          cursor=theme['cursor'], relief=theme['relief'], show='•')
entry_new_pass.bind("<Return>", change_pass_handler)
entry_new_pass.pack(side=TOP, anchor=CENTER)
button_pass_font = tk.Button(settings_frame3, text="CHANGE", activebackground=theme['button_bg_active'], width=15,
                             bg=theme['button_bg_positive'], relief=theme['relief'], command=lambda: change_password())
button_pass_font.pack(side=RIGHT, anchor=S)

settings_frame4 = LabelFrame(settings_frame, width=600, height=25, relief=FLAT, bg=theme['bg'])
settings_frame4.pack(side=TOP, pady=2, anchor=W)
theme0 = Radiobutton(settings_frame4, text="Light theme", activebackground=theme['bg'], bg=theme['bg'],
                     fg=theme['text_color'], font=theme['font_main'], variable=theme_var, value=0,
                     command=lambda: save_theme(), selectcolor=theme['bg'])
theme0.pack(side=LEFT)
theme1 = Radiobutton(settings_frame4, text="Dark theme", activebackground=theme['bg'], bg=theme['bg'],
                     fg=theme['text_color'], font=theme['font_main'], variable=theme_var, value=1,
                     command=lambda: save_theme(), selectcolor=theme['bg'])
theme1.pack(side=LEFT)
theme2 = Radiobutton(settings_frame4, text="Custom theme", activebackground=theme['bg'], bg=theme['bg'],
                     fg=theme['text_color'], font=theme['font_main'], variable=theme_var, value=2,
                     command=lambda: save_theme(), selectcolor=theme['bg'])
theme2.pack(side=LEFT)
settings_frame12 = LabelFrame(settings_frame, width=600, height=25, relief=FLAT, bg=theme['bg'])
settings_frame12.pack(side=TOP, pady=2, anchor=CENTER)
button_export = tk.Button(settings_frame12, text="EXPORT DATA", bg=theme['button_bg_positive'],
                          activebackground=theme['button_bg_active'], width=113, relief=theme['relief'],
                          command=lambda: export_program_data())
button_import = tk.Button(settings_frame12, text="IMPORT DATA", bg=theme['button_bg_positive'],
                          activebackground=theme['button_bg_active'], width=113, relief=theme['relief'],
                          command=lambda: import_program_data())
button_export.pack(side=TOP, anchor=CENTER)
button_import.pack(side=TOP, pady=5, anchor=CENTER)
button_regenerate = tk.Button(settings_frame12, text="REGENERATE ENCRYPTION KEYS", bg=theme['button_bg_positive'],
                              activebackground=theme['button_bg_active'], width=113, relief=theme['relief'],
                              command=lambda: regenerate_keys())
button_regenerate.pack(side=TOP, anchor=CENTER)
# endregion
# region json
choices = {'flat', 'raised', 'sunken', 'groove', 'ridge'}
choices2 = {'arrow', 'circle', 'clock', 'cross', 'dotbox', 'exchange', 'fleur', 'heart', 'man', 'mouse', 'pirate',
            'plus', 'shuttle', 'sizing', 'spider', 'spraycan', 'star', 'target', 'tcross', 'trek', 'watch'}
theme_editor_window = Toplevel(root)
theme_editor_window.withdraw()
theme_editor_window.title("Theme editor")
theme_editor_window.geometry("500x550+{}+{}".format(w, h))
theme_editor_window.resizable(False, False)
theme_editor_window['bg'] = theme['bg']
test_color = LabelFrame(theme_editor_window, width=500, relief=FLAT, bg=theme['bg'])
test_color.pack(side=TOP)
label_text = tk.Label(test_color, font=theme['font_main'], text="Text color", fg=theme['text_color'],
                      bg=theme['bg'], width=25, anchor=W)
label_text.pack(side=LEFT)
entry_text = tk.Entry(test_color, font=12, width=25, fg=theme['text_color'], bg=theme['entry'],
                      relief=theme['relief'], cursor=theme['cursor'])
entry_text.pack(side=LEFT)
entry_color = LabelFrame(theme_editor_window, width=500, relief=FLAT, bg=theme['bg'])
entry_color.pack(side=TOP, pady=5)
label_entry = tk.Label(entry_color, font=theme['font_main'], text="Entry color", fg=theme['text_color'],
                       bg=theme['bg'], width=25, anchor=W)
label_entry.pack(side=LEFT)
entry_entry = tk.Entry(entry_color, font=12, width=25, fg=theme['text_color'], bg=theme['entry'],
                       relief=theme['relief'], cursor=theme['cursor'])
entry_entry.pack(side=LEFT)
widgets_relief = LabelFrame(theme_editor_window, width=500, relief=FLAT, bg=theme['bg'])
widgets_relief.pack(side=TOP)
label_relief = tk.Label(widgets_relief, font=theme['font_main'], text="Widgets relief", fg=theme['text_color'],
                        bg=theme['bg'], width=25, anchor=W)
label_relief.pack(side=LEFT)
popup_main = OptionMenu(widgets_relief, relief, *choices)
popup_main.pack(side=TOP)
popup_main.configure(width=31, relief=theme['relief'], fg=theme['text_color'], bg=theme['entry'],
                     activebackground=theme['entry'], highlightthickness=0)
popup_main["menu"].configure(bg=theme['entry'], fg=theme['text_color'], relief=theme['relief'],
                             activebackground=theme['button_bg_active'], borderwidth=0)
frame_relief = LabelFrame(theme_editor_window, width=500, relief=FLAT, bg=theme['bg'])
frame_relief.pack(side=TOP, pady=5)
label_frame_r = tk.Label(frame_relief, font=theme['font_main'], text="Frame relief", fg=theme['text_color'],
                         bg=theme['bg'], width=25, anchor=W)
label_frame_r.pack(side=LEFT)
popup_frames = OptionMenu(frame_relief, frames_relief, *choices)
popup_frames.pack(side=TOP)
popup_frames.configure(width=31, relief=theme['relief'], fg=theme['text_color'], bg=theme['entry'],
                       activebackground=theme['entry'], highlightthickness=0)
popup_frames["menu"].configure(bg=theme['entry'], fg=theme['text_color'], relief=theme['relief'],
                               activebackground=theme['button_bg_active'], borderwidth=0)
bg_frame = LabelFrame(theme_editor_window, width=500, relief=FLAT, bg=theme['bg'])
bg_frame.pack(side=TOP)
label_bg = tk.Label(bg_frame, font=theme['font_main'], text="Background color", fg=theme['text_color'],
                    bg=theme['bg'], width=25, anchor=W)
label_bg.pack(side=LEFT)
entry_bg = tk.Entry(bg_frame, font=12, width=25, fg=theme['text_color'], bg=theme['entry'],
                    relief=theme['relief'], cursor=theme['cursor'])
entry_bg.pack(side=LEFT)
sel_bg_frame = LabelFrame(theme_editor_window, width=500, relief=FLAT, bg=theme['bg'])
sel_bg_frame.pack(side=TOP)
label_sel_bg = tk.Label(sel_bg_frame, font=theme['font_main'], text="Select background", fg=theme['text_color'],
                        bg=theme['bg'], width=25, anchor=W)
label_sel_bg.pack(side=LEFT)
entry_sel_bg = tk.Entry(sel_bg_frame, font=12, width=25, fg=theme['text_color'], bg=theme['entry'],
                        relief=theme['relief'], cursor=theme['cursor'])
entry_sel_bg.pack(side=LEFT)
font_frame = LabelFrame(theme_editor_window, width=500, relief=FLAT, bg=theme['bg'])
font_frame.pack(side=TOP, pady=5)
label_font = tk.Label(font_frame, font=theme['font_main'], text="Main font", fg=theme['text_color'],
                      bg=theme['bg'], width=25, anchor=W)
label_font.pack(side=LEFT)
entry_font = tk.Entry(font_frame, font=12, width=25, fg=theme['text_color'], bg=theme['entry'],
                      relief=theme['relief'], cursor=theme['cursor'])
entry_font.pack(side=LEFT)
font_users_frame = LabelFrame(theme_editor_window, width=500, relief=FLAT, bg=theme['bg'])
font_users_frame.pack(side=TOP)
label_font_u = tk.Label(font_users_frame, font=theme['font_main'], text="Users frame font", fg=theme['text_color'],
                        bg=theme['bg'], width=25, anchor=W)
label_font_u.pack(side=LEFT)
entry_font_u = tk.Entry(font_users_frame, font=12, width=25, fg=theme['text_color'], bg=theme['entry'],
                        relief=theme['relief'], cursor=theme['cursor'])
entry_font_u.pack(side=LEFT)
font_b_frame = LabelFrame(theme_editor_window, width=500, relief=FLAT, bg=theme['bg'])
font_b_frame.pack(side=TOP, pady=5)
label_font_b = tk.Label(font_b_frame, font=theme['font_main'], text="Buttons font", fg=theme['text_color'],
                        bg=theme['bg'], width=25, anchor=W)
label_font_b.pack(side=LEFT)
entry_font_b = tk.Entry(font_b_frame, font=12, width=25, fg=theme['text_color'], bg=theme['entry'],
                        relief=theme['relief'], cursor=theme['cursor'])
entry_font_b.pack(side=LEFT)
frame_bg_b = LabelFrame(theme_editor_window, width=500, relief=FLAT, bg=theme['bg'])
frame_bg_b.pack(side=TOP)
label_bg_b = tk.Label(frame_bg_b, font=theme['font_main'], text="Buttons background", fg=theme['text_color'],
                      bg=theme['bg'], width=25, anchor=W)
label_bg_b.pack(side=LEFT)
entry_bg_b = tk.Entry(frame_bg_b, font=12, width=25, fg=theme['text_color'], bg=theme['entry'],
                      relief=theme['relief'], cursor=theme['cursor'])
entry_bg_b.pack(side=LEFT)
frame_bg_b_pos = LabelFrame(theme_editor_window, width=500, relief=FLAT, bg=theme['bg'])
frame_bg_b_pos.pack(side=TOP, pady=5)
label_bg_b_pos = tk.Label(frame_bg_b_pos, font=theme['font_main'], text="Buttons background positive",
                          fg=theme['text_color'], bg=theme['bg'], width=25, anchor=W)
label_bg_b_pos.pack(side=LEFT)
entry_bg_b_pos = tk.Entry(frame_bg_b_pos, font=12, width=25, fg=theme['text_color'], bg=theme['entry'],
                          relief=theme['relief'], cursor=theme['cursor'])
entry_bg_b_pos.pack(side=LEFT)
frame_bg_b_neg = LabelFrame(theme_editor_window, width=500, relief=FLAT, bg=theme['bg'])
frame_bg_b_neg.pack(side=TOP)
label_bg_b_neg = tk.Label(frame_bg_b_neg, font=theme['font_main'], text="Buttons background negative",
                          fg=theme['text_color'], bg=theme['bg'], width=25, anchor=W)
label_bg_b_neg.pack(side=LEFT)
entry_bg_b_neg = tk.Entry(frame_bg_b_neg, font=12, width=25, fg=theme['text_color'], bg=theme['entry'],
                          relief=theme['relief'], cursor=theme['cursor'])
entry_bg_b_neg.pack(side=LEFT)
frame_b_act = LabelFrame(theme_editor_window, width=500, relief=FLAT, bg=theme['bg'])
frame_b_act.pack(side=TOP, pady=5)
label_b_act = tk.Label(frame_b_act, font=theme['font_main'], text="Buttons active background",
                       fg=theme['text_color'], bg=theme['bg'], width=25, anchor=W)
label_b_act.pack(side=LEFT)
entry_b_act = tk.Entry(frame_b_act, font=12, width=25, fg=theme['text_color'], bg=theme['entry'],
                       relief=theme['relief'], cursor=theme['cursor'])
entry_b_act.pack(side=LEFT)
frame_cursor = LabelFrame(theme_editor_window, width=500, relief=FLAT, bg=theme['bg'])
frame_cursor.pack(side=TOP)
label_cursor = tk.Label(frame_cursor, font=theme['font_main'], text="Input fields cursor",
                        fg=theme['text_color'], bg=theme['bg'], width=25, anchor=W)
label_cursor.pack(side=LEFT)
popup_cur = OptionMenu(frame_cursor, cursors, *choices2)
popup_cur.pack(side=TOP)
popup_cur.configure(width=31, relief=theme['relief'], fg=theme['text_color'], bg=theme['entry'],
                    activebackground=theme['entry'], highlightthickness=0, height=1)
popup_cur["menu"].configure(bg=theme['entry'], fg=theme['text_color'], relief=theme['relief'],
                            activebackground=theme['button_bg_active'], borderwidth=0)
# print(popup_cur.keys())
button_save = tk.Button(theme_editor_window, text="SAVE", bg=theme['button_bg_positive'], relief=theme['relief'],
                        activebackground=theme['button_bg_active'], width=64, command=lambda: theme_editor_save())
button_save.pack(side=TOP, pady=5)
# endregion
# region info
main1_frame = LabelFrame(root, width=850, height=500, relief=theme['relief'], bg=theme['bg'])
info_frame = LabelFrame(main1_frame, bg=theme['bg'], relief=theme['relief'])
info_frame.pack(side=LEFT, anchor=NW)

info_frame_2 = LabelFrame(info_frame, bg=theme['bg'], relief=theme['relief'])
info_frame_2.pack(side=TOP, anchor=NW)
entry_user_search = tk.Entry(info_frame_2, font=10, width=87, relief=theme['relief'], fg=theme['text_color'],
                             bg=theme['entry'], cursor=theme['cursor'])
entry_user_search.pack(side=LEFT, padx=3)
button_search = tk.Button(info_frame_2, text="SEARCH", activebackground=theme['button_bg_active'], width=8,
                          bg=theme['button_bg_positive'], relief=theme['relief'], command=lambda: search_user())
button_search.pack(side=LEFT, anchor=E, padx=3)
frame_users = Frame(info_frame, width=800, height=400)
frame_users.pack()

style = ttk.Style()
style.theme_use("clam")
style.configure("mystyle.Heading", background=theme['entry'], relief=theme['relief'], font=theme['font_users'])
style.configure("mystyle", highlightthickness=0, background=theme['entry'], bd=0, font=theme['font_users'])
style.layout("mystyle", [('mystyle.treearea', {})])
canvas_users = ttk.Treeview(frame_users, height=29, cursor='arrow', columns=(0, 1, 2), show='headings', style="mystyle")
scroll_users = Scrollbar(frame_users, command=canvas_users.yview, bg=theme['bg'])
scroll_users.pack(side=RIGHT, fill=Y)
canvas_users.pack(side=RIGHT, expand=True, fill=BOTH)
canvas_users.config(yscrollcommand=scroll_users.set)
canvas_users.heading(0, text="ID", anchor=W)
canvas_users.heading(1, text="Username", anchor=W)
canvas_users.heading(2, text="Last activity", anchor=W)
canvas_users.column(0, width=60, stretch=NO)
canvas_users.column(1, width=567)
canvas_users.column(2, width=200, stretch=NO)
canvas_users.tag_configure('bb', background=theme['entry'], foreground=theme['text_color'])

label_loading = Label(root, font=10, text="LOADING", fg=theme['text_color'], bg=theme['bg'])
# endregion
auto_login()
get_update_time()
if time_to_check is not None:
    if int(time_to_check) != -1:
        checker = threading.Thread(target=loop_get_msg, daemon=True)
        sch.enter(int(time_to_check), 1, loop_msg_func)
if __name__ == "__main__":
    root.title("Chat")
    root.geometry("200x165+{}+{}".format(w, h))
    root.resizable(False, False)
    root['bg'] = theme['bg']
    root.mainloop()
