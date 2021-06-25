# if res.status_code == 401 заменить на response_handler

import os
import platform
import threading
import schedule  # найти более оптимальную библиотеку
import tkinter as tk
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
elif platform.uname().system == "Darwin":
    keyring.set_keyring(Keyring())

backend_url = "http://chat-b4ckend.herokuapp.com/"

code = None
chats = {}
pin_chats = []
current_chat = "-1"
root = tk.Tk()
spacing, spacing_2 = 0, 0
w = root.winfo_screenwidth() // 2 - 140
h = root.winfo_screenheight() // 2 - 100
user_id, email, user_login, user_password, auth_token = '', '', '', '', ''
var = IntVar()
theme_var = IntVar()
private_key = rsa.PrivateKey(1, 2, 3, 4, 5)
files_dir = 'files'
time_to_check = 60.0
dt = datetime.now(timezone.utc).astimezone()
utc_diff = dt.utcoffset()
theme = {}

try:
    os.mkdir(files_dir)
except FileExistsError:
    pass


def set_theme():  # доделать для кнопок
    global theme
    temp = keyring.get_password('datachat', 'theme')
    if temp == "1":
        theme_var.set(1)
        theme = {"tc": "#ffffff",
                 "entry": "gray",
                 "relief": FLAT,
                 "frame_relief": FLAT,  # RIDGE
                 "bg": "#48494f",
                 "font10": Font(family='Candara', size=13),
                 "font_p": Font(family='Candara', size=15),
                 "button_font": Font(family='Candara', size=10),
                 "cursor": "pencil"}
    else:
        theme_var.set(0)
        theme = {"tc": "#000000",
                 "entry": None,
                 "relief": None,
                 "frame_relief": None,
                 "bg": None,
                 "font10": Font(family='Ubuntu', size=13),
                 "font_p": Font(family='Ubuntu', size=15),
                 "button_font": None,
                 "cursor": None}


set_theme()


def exception_handler(e):
    try:
        print(e)
    except Exception as er:
        print(er)


def response_handler(res: requests.models.Response):
    try:
        if res.status_code == 200:
            return res
        elif res.status_code == 401:
            print("Not authorized")
            return "retry"
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
        res = requests.post(f"{backend_url}auth", json={"login": log, "password": pas})
        return response_handler(res).json()
    except Exception as er:
        exception_handler(er)


def get_id(log):
    try:
        res = requests.get(f"{backend_url}user/get_id?login={log}")
        return response_handler(res).json()
    except Exception as er:
        exception_handler(er)


def get_user_nickname(user):
    try:
        res = requests.get(f"{backend_url}user/get_nickname?id={user}")
        return response_handler(res).json()
    except Exception as er:
        exception_handler(er)


def get_random_users():  # дописать
    try:
        res = requests.get(f"{backend_url}user/get_random")
        return response_handler(res).json()
    except Exception as er:
        exception_handler(er)


def get_pubkey(user):
    try:
        res = requests.get(f"{backend_url}user/get_pubkey?id={user}")
        return response_handler(res).json()
    except Exception as er:
        exception_handler(er)


def get_messages(cur_chat, is_chat):
    global user_login, user_password, auth_token
    try:
        res = requests.get(f"{backend_url}message/get?chat_id={cur_chat}&is_chat={is_chat}",
                           headers={'Authorization': f'Bearer {auth_token}'})
        if response_handler(res) == "retry":
            auth_token = check_password(user_login, user_password)
        res = requests.get(f"{backend_url}message/get?chat_id={cur_chat}&is_chat={is_chat}",
                           headers={'Authorization': f'Bearer {auth_token}'})
        try:
            return response_handler(res).json()
        except AttributeError:
            return None
    except Exception as er:
        exception_handler(er)


def can_use_login(log):
    try:
        res = requests.get(f"{backend_url}user/can_use_login?login={log}")
        return response_handler(res).json()
    except Exception as er:
        exception_handler(er)


def regenerate_keys():
    button_regenerate.update()
    global user_login, user_password, auth_token
    try:
        res = requests.put(f"{backend_url}user/update_pubkey", json={'pubkey': keys_generation()},
                           headers={'Authorization': f'Bearer {auth_token}'})
        if res.status_code == 401:
            auth_token = check_password(user_login, user_password)
            if requests.put(f"{backend_url}user/update_pubkey", json={'pubkey': keys_generation()},
                            headers={'Authorization': f'Bearer {auth_token}'}).json:
                messagebox.showinfo("Success", "Regeneration successful!")
            else:
                messagebox.showerror("Failed", "Regeneration failed!")
        else:
            if res.json:
                messagebox.showinfo("Success", "Regeneration successful!")
            else:
                messagebox.showerror("Failed", "Regeneration failed!")
    except Exception as er:
        exception_handler(er)


def get_chat_id(name: str):
    try:
        res = requests.get(f"{backend_url}chat/get_id?name={name}")
        return response_handler(res).json()
    except Exception as er:
        exception_handler(er)


def get_chat_name(group_id: str):
    try:
        res = requests.get(f"{backend_url}chat/get_name?group_id={group_id}")
        return response_handler(res).json()
    except Exception as er:
        exception_handler(er)


def get_user_groups(user: int):
    try:
        res = requests.get(f"{backend_url}user/get_groups?user_id={user}")
        return response_handler(res).json()
    except Exception as er:
        exception_handler(er)


def get_chat_users(name: str):
    try:
        res = requests.get(f"{backend_url}chat/get_users?name={name}")
        return response_handler(res).json()
    except Exception as er:
        exception_handler(er)


def upload_file(path: str):
    try:
        res = requests.post(f"{backend_url}file/upload", files={"file": open(path, "rb")})
        return response_handler(res).json()
    except Exception as er:
        exception_handler(er)


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


def fill_auto_login_file(lgn, psw):
    keyring.set_password('datachat', 'login', lgn)
    keyring.set_password('datachat', 'password', psw)


def login(*args):
    global user_login, user_id, user_password, auth_token
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
        auth_token = res
        if var.get() == 0:
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
        except Exception as er:
            exception_handler(er)
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
        button_chat.configure(bg="#2E8B57")
        button_info.configure(bg="#A9A9A9")
        button_settings.configure(bg="#A9A9A9")
        button_groups.configure(bg="#A9A9A9")
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
        button_chat.configure(bg="#A9A9A9")
        button_info.configure(bg="#A9A9A9")
        button_settings.configure(bg="#2E8B57")
        button_groups.configure(bg="#A9A9A9")
        main_frame.pack_forget()
        main1_frame.pack_forget()
        group_frame.pack_forget()
        settings_frame.pack(side=LEFT, anchor=N)
    elif menu == "info":
        button_info.update()
        button_chat.configure(bg="#A9A9A9")
        button_info.configure(bg="#2E8B57")
        button_settings.configure(bg="#A9A9A9")
        button_groups.configure(bg="#A9A9A9")
        main_frame.pack_forget()
        settings_frame.pack_forget()
        group_frame.pack_forget()
        main1_frame.pack(side=LEFT, anchor=NW)
        users_list = get_random_users()
        canvas_users.configure(state='normal')
        canvas_users.delete(0.0, END)
        for i in range(20):
            try:
                user = users_list[f'user_{i}']
                content = f"{user['id']}"
                while len(content) < 10:
                    content += " "
                content += f"{user['login']}\n"
                canvas_users.insert(END, content)
                canvas_users.update()
            except KeyError:
                break
        canvas_users.configure(state='disabled')
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
            chats[i] = tk.Button(menu_frame, text=i, bg='#A9A9A9', width=17, relief=theme['relief'],
                                 font=theme['button_font'])
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


def config(groups):  # потестить
    global chats
    """for i in range(len(chats)):
        try:
            print(i)
            chats[groups[i]].configure(command=lambda: change_group(get_chat_id(groups[i]), chats[groups[i]]))
        except IndexError:
            pass
    return"""
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


def send_message():
    global user_id, current_chat, user_login, user_password, auth_token
    button_send.update()
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
        date = datetime.utcnow().strftime('%d-%m-%Y %H:%M:%S')
        res = requests.post(f"{backend_url}message/send", json={"date": date, "sender": user_id,
                                                                "destination": to_id, "message": encrypt_msg,
                                                                "message1": encrypt_msg1},
                            headers={'Authorization': f'Bearer {auth_token}'})
        if res.status_code == 401:
            auth_token = check_password(user_login, user_password)
            requests.post(f"{backend_url}message/send", json={"date": date, "sender": user_id,
                                                              "destination": to_id, "message": encrypt_msg,
                                                              "message1": encrypt_msg1},
                          headers={'Authorization': f'Bearer {auth_token}'})
        entry_msg.delete(0, tk.END)
        get_message()
    except Exception as e:
        exception_handler(e)


def send_doc():
    button_img.update()
    global user_id, current_chat, auth_token, user_login, user_password
    try:
        path = filedialog.askopenfilename(filetypes=[("All files", "*.*")])
        if len(path) == 0:
            return
        res = requests.get(f"{backend_url}url/shorter?url={upload_file(path)}&destination={current_chat}",
                           headers={'Authorization': f'Bearer {auth_token}'})
        if res.status_code == 401:
            auth_token = check_password(user_login, user_password)
            requests.get(f"{backend_url}url/shorter?url={upload_file(path)}&destination={current_chat}",
                         headers={'Authorization': f'Bearer {auth_token}'})
        get_message()
    except Exception as e:
        exception_handler(e)


def get_message():
    button_refresh.update()
    global user_id, current_chat
    chat_nick = 0
    res = get_messages(current_chat, 0)
    if res is None:
        return
    try:
        canvas.configure(state='normal')
        canvas.delete(0.0, END)
        for i in range(2000):
            try:
                message = res[f"item_{i}"]
                if chat_nick == 0 and int(message["from_id"]) != user_id:
                    chat_nick = get_user_nickname(message["from_id"])
                nick = user_login if int(message["from_id"]) == user_id else chat_nick
                decrypt_msg = decrypt(int2bytes(message["message"]), int2bytes(message["message1"]))
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
    except Exception as er:
        exception_handler(er)


def get_private_key():
    try:
        global private_key
        private_key = rsa.PrivateKey.load_pkcs1(keyring.get_password('datachat', 'private_key').encode('utf-8'))
    except FileNotFoundError:
        pass


def create_chat():
    global user_id, auth_token, user_login, user_password
    button_c_chat.update()
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
        res = requests.post(f"{backend_url}chat/create", json={"name": name},
                            headers={'Authorization': f'Bearer {auth_token}'})
        if res.status_code == 401:
            auth_token = check_password(user_login, user_password)
            res = requests.post(f"{backend_url}chat/create", json={"name": name},
                                headers={'Authorization': f'Bearer {auth_token}'}).json()
        else:
            res = res.json()
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
    global user_id, current_chat, user_login, user_password, auth_token
    button_send2.update()
    message = entry_msg2.get()
    try:
        if len(message) == 0:
            messagebox.showerror('Input error', 'Fill all input fields')
            return
        name = get_chat_name(current_chat)
        users = get_chat_users(name)
        for i in users:
            encrypt_msg = encrypt(message.encode('utf-8'), get_pubkey(i[0]))
            date = datetime.utcnow().strftime('%d-%m-%Y %H:%M:%S')
            res = requests.post(f"{backend_url}message/send/chat",
                                json={"date": date, "sender": f"{current_chat}_{user_id}", "destination": i[0],
                                      "message": encrypt_msg}, headers={'Authorization': f'Bearer {auth_token}'})
            if res.status_code == 401:
                auth_token = check_password(user_login, user_password)
                requests.post(f"{backend_url}message/send/chat",
                              json={"date": date, "sender": f"{current_chat}_{user_id}", "destination": i[0],
                                    "message": encrypt_msg}, headers={'Authorization': f'Bearer {auth_token}'})
            entry_msg2.delete(0, tk.END)
        get_chat_message()
    except Exception as e:
        exception_handler(e)


def send_chat_doc():
    global user_id, current_chat, auth_token, user_login, user_password
    button_img2.update()
    try:
        path = filedialog.askopenfilename(filetypes=[("All files", "*.*")])
        if len(path) == 0:
            return
        name = get_chat_name(current_chat)
        users = get_chat_users(name)
        for i in users:
            res = requests.get(f"{backend_url}url/shorter/chat?url={upload_file(path)}&sender={current_chat}_{user_id}&"
                               f"destination={i[0]}", headers={'Authorization': f'Bearer {auth_token}'})
            if res.status_code == 401:
                auth_token = check_password(user_login, user_password)
                requests.get(f"{backend_url}url/shorter/chat?url={upload_file(path)}&sender={current_chat}_{user_id}&"
                             f"destination={i[0]}", headers={'Authorization': f'Bearer {auth_token}'})
        get_chat_message()
    except Exception as e:
        exception_handler(e)


def get_chat_message():
    global user_id, current_chat
    button_refresh2.update()
    res = get_messages(current_chat, 1)
    if res is None:
        return
    try:
        canvas_2.configure(state='normal')
        canvas_2.delete(0.0, END)
        for i in range(2000):
            try:
                message = res[f"item_{i}"]
                decrypt_msg = decrypt(int2bytes(message["message"]), int2bytes(message["message1"]))
                date = datetime.strptime(message["date"], "%Y-%m-%dT%H:%M:%S")
                nickname = get_user_nickname(message["from_id"].split('_', 1)[1])
                content = f'{str(date + utc_diff)[2:]} {nickname}: {decrypt_msg}\n'
                canvas_2.insert(END, content)
                canvas_2.update()
            except KeyError:
                break
        canvas_2.configure(state='disabled')
    except Exception as e:
        exception_handler(e)


def invite_to_group():
    global user_id, auth_token, user_login, user_password
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
        res = requests.post(f"{backend_url}chat/invite", json={"name": name, "user": int(inv_user)},
                            headers={'Authorization': f'Bearer {auth_token}'})
        if res.status_code == 401:
            auth_token = check_password(user_login, user_password)
            res = requests.post(f"{backend_url}chat/invite", json={"name": name, "user": int(inv_user)},
                                headers={'Authorization': f'Bearer {auth_token}'}).json()
        else:
            res = res.json()
        if not res:
            messagebox.showerror('Access error', "You are not chat's owner")
            return
        messagebox.showinfo('Success', "Success")
    except Exception as e:
        exception_handler(e)


def kick_from_group():
    global user_id, auth_token, user_login, user_password
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
        res = requests.post(f"{backend_url}chat/kick", json={"name": name, "user": int(kick_user)},
                            headers={'Authorization': f'Bearer {auth_token}'})
        if res.status_code == 401:
            auth_token = check_password(user_login, user_password)
            res = requests.post(f"{backend_url}chat/kick", json={"name": name, "user": int(kick_user)},
                                headers={'Authorization': f'Bearer {auth_token}'}).json()
        else:
            res = res.json()
        if not res:
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
        res = requests.post(f"{backend_url}recovery/validate", json={"code": entry_code.get(),
                                                                     "login": entry_log.get()}).json()
        if not res:
            messagebox.showerror('Input error', 'Incorrect code')
            return
        recovery_frame.pack_forget()
        root.geometry("200x130+{}+{}".format(w, h))
        new_pass_frame.pack(side=TOP, anchor=CENTER)
    except Exception as er:
        exception_handler(er)


def change_password():
    global user_login, auth_token, user_login, user_password
    button_pass_font.update()
    try:
        hashed_pass = bcrypt.hashpw(entry_new_pass.get().encode('utf-8'), bcrypt.gensalt())
        hashed_pass = str(hashed_pass)[2:-1]
        res = requests.put(f"{backend_url}user/update_password", json={"old_password": entry_old_pass.get(),
                                                                       "new_password": hashed_pass},
                           headers={'Authorization': f'Bearer {auth_token}'})
        if res.status_code == 401:
            auth_token = check_password(user_login, user_password)
            res = requests.put(f"{backend_url}user/update_password", json={"old_password": entry_old_pass.get(),
                                                                           "new_password": hashed_pass},
                               headers={'Authorization': f'Bearer {auth_token}'}).json()
        else:
            res = res.json()
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
                res = requests.post(f"{backend_url}recovery/validate", json={"code": code,
                                                                             "login": user_login,
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
                    messagebox.showerror("Failed", "Password has not been changed")
    except Exception as er:
        exception_handler(er)


def pass_code():
    try:
        res = requests.post(f"{backend_url}recovery/send?login={entry_log.get()}").json()
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
    canvas.configure(state='normal')
    canvas.delete(0.0, END)
    canvas.configure(state='disable')
    get_message()


def search_user():
    res = entry_user_search.get()
    if len(res) == 0:
        return
    users_list = requests.get(f'{backend_url}user/find?login={res}').json()
    canvas_users.configure(state='normal')
    canvas_users.delete(0.0, END)
    for i in range(20):
        try:
            user = users_list[f'user_{i}']
            content = f"{user['id']}"
            while len(content) < 10:
                content += " "
            content += f"{user['login']}\n"
            canvas_users.insert(END, content)
            canvas_users.update()
        except KeyError:
            break
    canvas_users.configure(state='disabled')


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


def unpin_chat(l_frame, id):
    try:
        pin_chats.remove(l_frame)
        l_frame.pack_forget()
        if id == 1:
            chat = keyring.get_password('datachat', 'pin2')
            if chat is not None:
                keyring.set_password('datachat', 'pin1', chat)
            chat = keyring.get_password('datachat', 'pin3')
            if chat is not None:
                keyring.set_password('datachat', 'pin2', chat)
            keyring.delete_password('datachat', 'pin3')
        elif id == 2:
            chat = keyring.get_password('datachat', 'pin3')
            if chat is not None:
                keyring.set_password('datachat', 'pin2', chat)
            keyring.delete_password('datachat', 'pin3')
        else:
            keyring.delete_password('datachat', 'pin3')
    except Exception as er:
        exception_handler(er)


def pin_constructor(text, chat, id):
    try:
        local_frame = tk.LabelFrame(menu_frame, width=150, height=50, relief=FLAT, bg=theme['bg'])
        button1 = tk.Button(local_frame, text=text, bg='#A9A9A9', width=13, relief=theme['relief'],
                            font=theme['button_font'], command=lambda: (menu_navigation("chat"), open_chat(chat)))
        button2 = tk.Button(local_frame, text='-', bg='#B00000', width=2, relief=theme['relief'],
                            font=theme['button_font'], command=lambda: unpin_chat(local_frame, id))
        button1.pack(side=LEFT, anchor=N)
        button2.pack(side=LEFT, anchor=N, padx=3)
        local_frame.pack(side=TOP, pady=1, anchor=N)
        pin_chats.append(local_frame)
    except Exception as er:
        exception_handler(er)


def get_pin_chats():
    global pin_chats
    try:
        for i in range(3):
            pin = keyring.get_password('datachat', f'pin{i + 1}')
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
    keyring.set_password('datachat', 'theme', theme_var.get())
    messagebox.showinfo("Success!", "Theme will be changed on next launch!")


def get_update_time():
    global time_to_check
    if int(time_to_check) == 30:
        time_to_check = 45
        label_check2.configure(text='45 Sec')
    elif int(time_to_check) == 45:
        time_to_check = 60
        label_check2.configure(text='1 Min')
    elif int(time_to_check) == 60:
        time_to_check = -1
        label_check2.configure(text='Never')
    elif int(time_to_check) == -1:
        time_to_check = 30
        label_check2.configure(text='30 Sec')
    label_check2.update()


def auto_check():
    global time_to_check
    if int(time_to_check) == 30:
        time_to_check = 45
        label_check2.configure(text='45 Sec')
    elif int(time_to_check) == 45:
        time_to_check = 60
        label_check2.configure(text='1 Min')
    elif int(time_to_check) == 60:
        time_to_check = -1
        label_check2.configure(text='Never')
    elif int(time_to_check) == -1:
        time_to_check = 30
        label_check2.configure(text='30 Sec')
    label_check2.update()
    keyring.set_password('datachat', 'update', str(time_to_check))


def loop_msg_func():
    print('check')
    global auth_token, user_login, user_password
    if auth_token == '':
        return
    res = requests.get(f"{backend_url}message/loop",
                       headers={'Authorization': f'Bearer {auth_token}'})
    if res.status_code == 401:
        auth_token = check_password(user_login, user_password)
        res = requests.get(f"{backend_url}message/loop",
                           headers={'Authorization': f'Bearer {auth_token}'}).json()
    else:
        res = res.json()
    if res is not None:
        messagebox.showinfo('New messages!', 'You have new messages in chats: ' + res)
    if current_chat != '-1':
        if current_chat[0] != 'g':
            get_message()
        elif current_chat[0] == 'g':
            get_chat_message()


def loop_get_msg():
    while True:
        schedule.run_pending()


def api_awake():
    requests.head(f"{backend_url}api/awake")


awake_thread = threading.Thread(target=api_awake, daemon=True)
awake_thread.start()
"""m = Menu(root)
root.config(menu=m)
fm = Menu(m)
m.add_cascade(label="Файл", menu=fm)"""

# region auth
auth_frame = LabelFrame(root, width=200, height=130, relief=FLAT, bg=theme['bg'])
auth_frame.pack(side=TOP, anchor=CENTER)
label_user = tk.Label(auth_frame, font=theme['font10'], text="Username:", bg=theme['bg'],
                      fg=theme['tc'], width=19, anchor=W)
label_user.pack(side=TOP, anchor=S)
entry_log = tk.Entry(auth_frame, font=12, width=20, fg=theme['tc'], bg=theme['entry'], relief=theme['relief'],
                     cursor=theme['cursor'])
entry_log.bind("<Return>", login_handler)
entry_log.pack(side=TOP)
label_password = tk.Label(auth_frame, font=theme['font10'], text="Password:", bg=theme['bg'],
                          fg=theme['tc'], width=19, anchor=W)
label_password.pack(side=TOP, anchor=S)
entry_pass = tk.Entry(auth_frame, font=12, width=20, fg=theme['tc'], bg=theme['entry'], relief=theme['relief'],
                      cursor=theme['cursor'], show='•')
entry_pass.bind("<Return>", login)
entry_pass.pack(side=TOP)
check_remember = tk.Checkbutton(auth_frame, font=theme['font10'], fg=theme['tc'], bg=theme['bg'], text='Remember me',
                                activebackground=theme['bg'], selectcolor=theme['bg'], variable=var)
check_remember.pack(side=TOP, anchor=S)
button_login = tk.Button(auth_frame, text="LOGIN", bg='#2E8B57', width=11, command=lambda: login(),
                         relief=theme['relief'], font=theme['button_font'])
button_login.pack(side=LEFT, pady=3, anchor=CENTER)
button_reg_m = tk.Button(auth_frame, text="REGISTER", bg='#2E8B57', width=11, command=lambda: show_reg_frame(),
                         relief=theme['relief'], font=theme['button_font'])
button_reg_m.pack(side=RIGHT, pady=3, anchor=CENTER)
button_reg = tk.Button(auth_frame, text="REGISTER", bg='#2E8B57', width=11, command=lambda: register(),
                       relief=theme['relief'], font=theme['button_font'])
button_login_b = tk.Button(auth_frame, text="BACK", bg='#2E8B57', width=11, command=lambda: back_to_login(),
                           relief=theme['relief'], font=theme['button_font'])
# endregion
# region reg
recovery_frame = LabelFrame(root, width=200, height=130, relief=FLAT, bg=theme['bg'])
label_code = tk.Label(recovery_frame, font=theme['font10'], text="Code:", fg=theme['tc'], bg=theme['bg'],
                      width=19, anchor=W)
label_code.pack(side=TOP, anchor=S)
entry_code = tk.Entry(recovery_frame, font=12, width=20, fg=theme['tc'], bg=theme['entry'], relief=theme['relief'],
                      cursor=theme['cursor'])
entry_code.pack(side=TOP)
button_code = tk.Button(recovery_frame, text="SEND", bg='#2E8B57', width=11, command=lambda: new_pass_menu(),
                        relief=theme['relief'], font=theme['button_font'])
button_code.pack(side=RIGHT, pady=3, anchor=CENTER)
# endregion
# region new pass
new_pass_frame = LabelFrame(root, width=200, height=130, relief=FLAT, bg=theme['bg'])
label_code = tk.Label(new_pass_frame, font=theme['font10'], text="New Password:", fg=theme['tc'], bg=theme['bg'],
                      width=19, anchor=W)
label_code.pack(side=TOP, anchor=S)
entry_new_p = tk.Entry(new_pass_frame, font=12, width=20, fg=theme['tc'], bg=theme['entry'], cursor=theme['cursor'],
                       show='•')
entry_new_p.pack(side=TOP)
label_code2 = tk.Label(new_pass_frame, font=theme['font10'], text="Repeat Password:", fg=theme['tc'], bg=theme['bg'],
                       width=19, anchor=W)
label_code2.pack(side=TOP, anchor=S)
entry_new_p2 = tk.Entry(new_pass_frame, font=12, width=20, fg=theme['tc'], bg=theme['entry'], cursor=theme['cursor'],
                        show='•')
entry_new_p2.pack(side=TOP)
button_code = tk.Button(new_pass_frame, text="SET", bg='#2E8B57', width=11, command=lambda: set_new_pass(),
                        relief=theme['relief'], font=theme['button_font'])
button_code.pack(side=RIGHT, pady=3, anchor=CENTER)
# endregion
# region email
label_email = tk.Label(auth_frame, font=theme['font10'], text="Email:", fg=theme['tc'], bg=theme['bg'], width=19,
                       anchor=W)
entry_email = tk.Entry(auth_frame, font=12, width=20, fg=theme['tc'], bg=theme['entry'], relief=theme['relief'],
                       cursor=theme['cursor'])
# endregion
# region main menu
main_frame = LabelFrame(root, width=850, height=500, bg=theme['bg'], relief=theme['relief'])
group_frame = LabelFrame(root, width=850, height=500, bg=theme['bg'], relief=theme['relief'])
settings_frame = LabelFrame(root, width=600, height=500, bg=theme['bg'], relief=theme['frame_relief'])
menu_frame = LabelFrame(root, width=150, height=500, relief=FLAT, bg=theme['bg'])
button_chat = tk.Button(menu_frame, text="CHAT", bg='#2E8B57', width=17, relief=theme['relief'],
                        command=lambda: menu_navigation("chat"), font=theme['button_font'])
button_chat.pack(side=TOP, anchor=N)
button_info = tk.Button(menu_frame, text="INFO", bg='#A9A9A9', width=17, relief=theme['relief'],
                        command=lambda: menu_navigation("info"), font=theme['button_font'])
button_info.pack(side=TOP, pady=5, anchor=N)
button_settings = tk.Button(menu_frame, text="SETTINGS", bg='#A9A9A9', width=17, relief=theme['relief'],
                            command=lambda: menu_navigation("set"), font=theme['button_font'])
button_settings.pack(side=TOP, anchor=N)
button_groups = tk.Button(menu_frame, text="GROUPS", bg='#A9A9A9', width=17, relief=theme['relief'],
                          command=lambda: menu_navigation("group"), font=theme['button_font'])
button_groups.pack(side=TOP, pady=5, anchor=N)
label_line1 = tk.Label(menu_frame, font=theme['font10'], text="-" * 20, fg=theme['tc'], bg=theme['bg'])
label_line1.pack(side=TOP, anchor=N)
label_fixed = tk.Label(menu_frame, font=theme['font10'], text="PIN CHATS", fg=theme['tc'], bg=theme['bg'])
label_fixed.pack(side=TOP, anchor=N)
get_pin_chats()
label_line2 = tk.Label(menu_frame, font=theme['font10'], text="-" * 20, fg=theme['tc'], bg=theme['bg'])
label_line2.pack(side=TOP, anchor=N)
button_logout = tk.Button(menu_frame, text="LOGOUT", bg='#B22222', width=17, relief=theme['relief'],
                          command=lambda: logout(), font=theme['button_font'])
button_logout.pack(side=BOTTOM, pady=5, anchor=N)
button_back = tk.Button(menu_frame, text="BACK", bg='#B22222', width=17, relief=theme['relief'],
                        command=lambda: menu_navigation("chat"), font=theme['button_font'])
main2_frame = LabelFrame(main_frame, width=600, height=350, relief=FLAT, bg=theme['bg'])
main2_frame.pack(side=TOP, anchor=CENTER)
main2_frame2 = LabelFrame(group_frame, width=600, height=350, relief=FLAT, bg=theme['bg'])
main2_frame2.pack(side=TOP, anchor=CENTER)
# endregion
# region chat
chat_frame = LabelFrame(main2_frame, width=600, height=25, relief=FLAT, bg=theme['bg'])
chat_frame.pack(side=TOP, pady=2, anchor=N)
label_chat_id = tk.Label(chat_frame, font=theme['font10'], text="Current chat with: ", fg=theme['tc'], bg=theme['bg'],
                         width=25, anchor=W)
label_chat_id.pack(side=LEFT, anchor=W)
entry_chat_id = tk.Entry(chat_frame, font=12, width=20, fg=theme['tc'], bg=theme['entry'], relief=theme['relief'],
                         cursor='pencil')
entry_chat_id.pack(side=LEFT, padx=165, anchor=CENTER)
button_chat_id = tk.Button(chat_frame, text="OPEN", bg='#2E8B57', width=15, relief=theme['relief'],
                           command=lambda: open_chat(entry_chat_id.get()))
button_chat_id.pack(side=RIGHT, anchor=E)

frame = Frame(main2_frame, width=850, height=450)
frame.pack()
canvas = Text(frame, fg=theme['tc'], bg=theme['entry'], width=105, cursor='arrow')
scroll = Scrollbar(frame, command=canvas.yview, bg=theme['bg'])
scroll.pack(side=RIGHT, fill=Y)
canvas.pack(side=RIGHT, expand=True, fill=BOTH)
canvas.config(yscrollcommand=scroll.set)
canvas.configure(state='disabled')

frame_2 = Frame(main2_frame2, width=850, height=500)
frame_2.pack()
canvas_2 = Text(frame_2, fg=theme['tc'], bg=theme['entry'], width=105, height=27, cursor='arrow')
scroll_2 = Scrollbar(frame_2, command=canvas_2.yview, bg=theme['bg'])
scroll_2.pack(side=RIGHT, fill=Y)
canvas_2.pack(side=RIGHT, expand=True, fill=BOTH)
canvas_2.config(yscrollcommand=scroll_2.set)
canvas_2.configure(state='disabled')

button_refresh = tk.Button(main_frame, text="REFRESH", bg='#2E8B57', width=120, relief=theme['relief'],
                           command=lambda: get_message())
button_refresh.pack(side=TOP, pady=3, anchor=CENTER)
entry_msg = tk.Entry(main_frame, font=10, width=85, relief=theme['relief'], fg=theme['tc'], bg=theme['entry'],
                     cursor=theme['cursor'])
entry_msg.bind("<Return>", send_message_handler)
entry_msg.pack(side=LEFT, padx=3)
button_img = tk.Button(main_frame, text="➕", bg='#2E8B57', width=3, relief=theme['relief'],
                       command=lambda: send_doc(), state='disabled')
button_img.pack(side=LEFT, anchor=E)
button_send = tk.Button(main_frame, text="SEND", bg='#2E8B57', width=8, relief=theme['relief'],
                        command=lambda: send_message(),
                        state='disabled')
button_send.pack(side=LEFT, anchor=E, padx=3)

button_refresh2 = tk.Button(group_frame, text="REFRESH", bg='#2E8B57', width=121, relief=theme['relief'],
                            command=lambda: get_chat_message())
button_refresh2.pack(side=TOP, pady=3, anchor=CENTER)
entry_msg2 = tk.Entry(group_frame, font=10, width=85, relief=theme['relief'], fg=theme['tc'], bg=theme['entry'],
                      cursor=theme['cursor'])
# entry_msg2.bind("<Return>", send_chat_message())
entry_msg2.pack(side=LEFT, padx=3)
button_img2 = tk.Button(group_frame, text="➕", bg='#2E8B57', width=3, relief=theme['relief'], state='disabled',
                        command=lambda: send_chat_doc())
button_img2.pack(side=LEFT, anchor=E)
button_send2 = tk.Button(group_frame, text="SEND", bg='#2E8B57', width=8, relief=theme['relief'], state='disabled',
                         command=lambda: send_chat_message())
button_send2.pack(side=LEFT, anchor=E, padx=3)
entry_log.focus_set()
# root.after(500, loop)
# endregion
# region settings
settings_frame_2 = LabelFrame(settings_frame, width=600, height=25, relief=FLAT, bg=theme['bg'])
settings_frame_2.pack(side=TOP, pady=2, anchor=N)
label_check = tk.Label(settings_frame_2, font=10, text="  Update frequency:", fg=theme['tc'], bg=theme['bg'], width=18,
                       anchor=W)
label_check.pack(side=LEFT, anchor=W)
label_check2 = tk.Label(settings_frame_2, font=12, text='1 min', width=20, fg=theme['tc'], bg=theme['bg'])
label_check2.pack(side=LEFT, padx=170, anchor=CENTER)
button_check_msg = tk.Button(settings_frame_2, text="UPDATE", bg='#2E8B57', width=15, relief=theme['relief'],
                             command=lambda: auto_check())
button_check_msg.pack(side=RIGHT, anchor=E)

settings_frame7 = LabelFrame(settings_frame, width=600, height=25, relief=FLAT, bg=theme['bg'])
settings_frame7.pack(side=TOP, pady=2, anchor=N)
label_chat = tk.Label(settings_frame7, font=10, text="  Create chat:", fg=theme['tc'], bg=theme['bg'], width=18,
                      anchor=W)
label_chat.pack(side=LEFT, anchor=W)
entry_chat = tk.Entry(settings_frame7, font=12, width=20, fg=theme['tc'], bg=theme['entry'], cursor=theme['cursor'],
                      relief=theme['relief'])
entry_chat.pack(side=LEFT, padx=170, anchor=CENTER)
button_c_chat = tk.Button(settings_frame7, text="CREATE", bg='#2E8B57', width=15, relief=theme['relief'],
                          command=lambda: create_chat())
button_c_chat.pack(side=RIGHT, anchor=E)

settings_frame11 = LabelFrame(settings_frame, width=600, height=25, relief=FLAT, bg=theme['bg'])
settings_frame11.pack(side=TOP, pady=2, anchor=N)
label_pin = tk.Label(settings_frame11, font=10, text="  Pin chat:", fg=theme['tc'], bg=theme['bg'], width=18, anchor=W)
label_pin.pack(side=LEFT, anchor=W)
entry_pin = tk.Entry(settings_frame11, font=12, width=20, fg=theme['tc'], bg=theme['entry'], cursor=theme['cursor'],
                     relief=theme['relief'])
entry_pin.pack(side=LEFT, padx=170, anchor=CENTER)
button_pin = tk.Button(settings_frame11, text="PIN", bg='#2E8B57', width=15, relief=theme['relief'],
                       command=lambda: pin_chat())
button_pin.pack(side=RIGHT, anchor=E)

settings_frame8 = LabelFrame(settings_frame, width=600, height=25, relief=FLAT, bg=theme['bg'])
settings_frame8.pack(side=TOP, pady=2, anchor=N)
settings_frame9 = LabelFrame(settings_frame8, width=600, height=25, relief=FLAT, bg=theme['bg'])
settings_frame9.pack(side=LEFT, pady=2, anchor=N)
label_inv_id = tk.Label(settings_frame9, font=10, text="  ID to invite:", fg=theme['tc'], bg=theme['bg'], width=18,
                        anchor=W)
label_inv_id.pack(side=TOP, anchor=W)
entry_inv_id = tk.Entry(settings_frame9, font=12, width=20, fg=theme['tc'], bg=theme['entry'], cursor=theme['cursor'],
                        relief=theme['relief'])
entry_inv_id.pack(side=TOP, anchor=CENTER)
settings_frame10 = LabelFrame(settings_frame8, width=600, height=25, relief=FLAT, bg=theme['bg'])
settings_frame10.pack(side=LEFT, pady=2, padx=158, anchor=N)
label_gr_toinv = tk.Label(settings_frame10, font=10, text="Group id:", fg=theme['tc'], bg=theme['bg'], width=18,
                          anchor=W)
label_gr_toinv.pack(side=TOP, anchor=W)
entry_gr_toinv = tk.Entry(settings_frame10, font=12, width=20, fg=theme['tc'], bg=theme['entry'],
                          cursor=theme['cursor'], relief=theme['relief'])
entry_gr_toinv.pack(side=TOP, anchor=CENTER)
button_invite = tk.Button(settings_frame8, text="INVITE", bg='#2E8B57', width=15, relief=theme['relief'],
                          command=lambda: invite_to_group())
button_invite.pack(side=RIGHT, anchor=S)

settings_frame20 = LabelFrame(settings_frame, width=600, height=25, relief=FLAT, bg=theme['bg'])
settings_frame20.pack(side=TOP, pady=2, anchor=N)
settings_frame21 = LabelFrame(settings_frame20, width=600, height=25, relief=FLAT, bg=theme['bg'])
settings_frame21.pack(side=LEFT, pady=2, anchor=N)
label_kick_id = tk.Label(settings_frame21, font=10, text="  ID to kick:", fg=theme['tc'], bg=theme['bg'], width=18,
                         anchor=W)
label_kick_id.pack(side=TOP, anchor=W)
entry_kick_id = tk.Entry(settings_frame21, font=12, width=20, fg=theme['tc'], bg=theme['entry'], cursor=theme['cursor'],
                         relief=theme['relief'])
entry_kick_id.pack(side=TOP, anchor=CENTER)
settings_frame10 = LabelFrame(settings_frame20, width=600, height=25, relief=FLAT, bg=theme['bg'])
settings_frame10.pack(side=LEFT, pady=2, padx=158, anchor=N)
label_gr_tokick = tk.Label(settings_frame10, font=10, text="Group id:", fg=theme['tc'], bg=theme['bg'], width=18,
                           anchor=W)
label_gr_tokick.pack(side=TOP, anchor=W)
entry_gr_tokick = tk.Entry(settings_frame10, font=12, width=20, fg=theme['tc'], bg=theme['entry'],
                           cursor=theme['cursor'], relief=theme['relief'])
entry_gr_tokick.pack(side=TOP, anchor=CENTER)
button_kick = tk.Button(settings_frame20, text="KICK", bg='#2E8B57', width=15, relief=theme['relief'],
                        command=lambda: kick_from_group())
button_kick.pack(side=RIGHT, anchor=S)

settings_frame3 = LabelFrame(settings_frame, width=600, height=25, relief=FLAT, bg=theme['bg'])
settings_frame3.pack(side=TOP, pady=2, anchor=N)
settings_frame5 = LabelFrame(settings_frame3, width=600, height=25, relief=FLAT, bg=theme['bg'])
settings_frame5.pack(side=LEFT, pady=2, anchor=N)
label_old_pass = tk.Label(settings_frame5, font=10, text="  Current password:", fg=theme['tc'], bg=theme['bg'],
                          width=18, anchor=W)
label_old_pass.pack(side=TOP, anchor=W)
entry_old_pass = tk.Entry(settings_frame5, font=12, width=20, fg=theme['tc'], bg=theme['entry'], cursor=theme['cursor'],
                          relief=theme['relief'], show='•')
entry_old_pass.bind("<Return>", change_pass_handler)
entry_old_pass.pack(side=TOP, anchor=CENTER)
settings_frame6 = LabelFrame(settings_frame3, width=600, height=25, relief=FLAT, bg=theme['bg'])
settings_frame6.pack(side=LEFT, pady=2, padx=158, anchor=N)
label_new_pass = tk.Label(settings_frame6, font=10, text="New password:", fg=theme['tc'], bg=theme['bg'], width=18,
                          anchor=W)
label_new_pass.pack(side=TOP, anchor=W)
entry_new_pass = tk.Entry(settings_frame6, font=12, width=20, fg=theme['tc'], bg=theme['entry'], cursor=theme['cursor'],
                          relief=theme['relief'], show='•')
entry_new_pass.bind("<Return>", change_pass_handler)
entry_new_pass.pack(side=TOP, anchor=CENTER)
button_pass_font = tk.Button(settings_frame3, text="CHANGE", bg='#2E8B57', width=15, relief=theme['relief'],
                             command=lambda: change_password())
button_pass_font.pack(side=RIGHT, anchor=S)

settings_frame4 = LabelFrame(settings_frame, width=600, height=25, relief=FLAT, bg=theme['bg'])
settings_frame4.pack(side=TOP, pady=2, anchor=W)
theme0 = Radiobutton(settings_frame4, text="Light theme", bg=theme['bg'], fg=theme['tc'], font=theme['font10'],
                     variable=theme_var, value=0, command=lambda: save_theme())
theme0.pack(side=LEFT)
theme1 = Radiobutton(settings_frame4, text="Dark theme", bg=theme['bg'], fg=theme['tc'], font=theme['font10'],
                     variable=theme_var, value=1, command=lambda: save_theme())
theme1.pack(side=LEFT)
button_regenerate = tk.Button(settings_frame, text="REGENERATE ENCRYPTION KEYS", bg='#2E8B57', width=113,
                              relief=theme['relief'], command=lambda: regenerate_keys())
button_regenerate.pack(side=TOP, anchor=CENTER)
# endregion
# region info
main1_frame = LabelFrame(root, width=850, height=500, relief=theme['relief'], bg=theme['bg'])
info_frame = LabelFrame(main1_frame, bg=theme['bg'], relief=theme['relief'])
info_frame.pack(side=LEFT, anchor=NW)

info_frame_2 = LabelFrame(info_frame, bg=theme['bg'], relief=theme['relief'])
info_frame_2.pack(side=TOP, anchor=NW)
entry_user_search = tk.Entry(info_frame_2, font=10, width=87, relief=theme['relief'], fg=theme['tc'], bg=theme['entry'],
                             cursor=theme['cursor'])
entry_user_search.pack(side=LEFT, padx=3)
button_search = tk.Button(info_frame_2, text="SEARCH", bg='#2E8B57', width=8, relief=theme['relief'],
                          command=lambda: search_user())
button_search.pack(side=LEFT, anchor=E, padx=3)
frame_users = Frame(info_frame, width=800, height=400)
frame_users.pack()
canvas_users = Text(frame_users, fg=theme['tc'], bg=theme['entry'], font=theme['font_p'], width=90, height=29,
                    cursor='arrow')
scroll_users = Scrollbar(frame_users, command=canvas_users.yview, bg=theme['bg'])
scroll_users.pack(side=RIGHT, fill=Y)
canvas_users.pack(side=RIGHT, expand=True, fill=BOTH)
canvas_users.config(yscrollcommand=scroll_users.set)
canvas_users.configure(state='disabled')

label_loading = Label(root, font=10, text="LOADING", fg=theme['tc'], bg=theme['bg'])
# endregion
auto_login()
get_update_time()
time_to_check = keyring.get_password('datachat', 'update')
if time_to_check is not None:
    if int(time_to_check) != -1:
        checker = threading.Thread(target=loop_get_msg, daemon=True)
        schedule.every(int(time_to_check)).seconds.do(loop_msg_func)

if __name__ == "__main__":
    root.title("Chat")
    root.geometry("200x165+{}+{}".format(w, h))
    root.resizable(False, False)
    root['bg'] = theme['bg']
    root.mainloop()
