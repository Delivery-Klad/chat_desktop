from os import mkdir, remove, path, listdir, replace
from sys import platform, exc_info
from pathlib import Path
from json import dump, load
from requests import request
from datetime import datetime, timezone

from PIL import Image
from qrcode import make
from bcrypt import hashpw, gensalt
from keyring import errors, set_keyring, set_password, get_password, delete_password
from rsa import PrivateKey, PublicKey, encrypt, decrypt, newkeys
from rsa.transform import int2bytes, bytes2int

from tkinter.font import Font
from tkinter.ttk import Style, Treeview, Scrollbar
from tkinter import IntVar, StringVar, Toplevel, TOP, LEFT, RIGHT, CENTER, WORD, END, FLAT, GROOVE, Y, N, W, E, S, NW, \
    NO, BOTH, Canvas, PhotoImage, OptionMenu, Radiobutton, Checkbutton, LabelFrame, Label, Button, Frame, TclError,\
    Tk, Text, Entry, filedialog


app_ver = 3.8
debug = False
chats, theme = {}, {}
current_chat = "-1"
root = Tk()
spacing, spacing_2, x, y = 0, 0, 0, 0
w = root.winfo_screenwidth() // 2 - 80
h = root.winfo_screenheight() // 2 - 130
code, user_id, email, user_login, user_password, access_token = "", "", "", "", "", ""
remember_var, theme_var = IntVar(), IntVar()
relief, frames_relief, cursors = StringVar(), StringVar(), StringVar()
private_key = PrivateKey(1, 2, 3, 4, 5)
time_to_check = 60.0
utc_diff = datetime.now(timezone.utc).astimezone().utcoffset()
chat_labels = []

if not debug:
    backend_url = "https://chat-b4ckend.herokuapp.com/"
else:
    backend_url = "http://localhost:8000/"

if "win" in platform.lower():
    from keyring.backends.Windows import WinVaultKeyring
    set_keyring(WinVaultKeyring())
    files_dir = str(Path.home()) + "/AppData/Roaming/PojiloiChat"
elif "darwin" in platform.lower():
    from keyring.backends.macOS import Keyring
    set_keyring(Keyring)
    files_dir = str(Path.home()) + "/Library/Application Support/PojiloiChat"
elif "linux" in platform.lower():
    from keyring.backends.kwallet import KeyringBackend
    set_keyring(KeyringBackend)
    files_dir = str(Path.home()) + "/.local/share/PojiloiChat"


class ScrollableFrame(Frame):
    def __init__(self, container, *args, **kwargs):
        super().__init__(container, *args, **kwargs)
        _canvas = Canvas(self, width=230, height=500, bg=theme['bg'], relief=FLAT, highlightthickness=0)
        scrollbar = Scrollbar(self, orient="vertical", command=_canvas.yview)
        self.scrollable_frame = Frame(_canvas, bg=theme['bg'], relief=FLAT)
        self.scrollable_frame.bind("<Configure>", lambda e: _canvas.configure(scrollregion=_canvas.bbox("all")))
        _canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        _canvas.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=LEFT, fill=Y)
        _canvas.pack(side=LEFT, fill=BOTH, expand=True)


class CustomBox:
    def __init__(self):
        res = root.geometry().split("+")
        resolution = res[0].split("x")
        local_w = int(res[1]) + int(int(resolution[0]) / 2) - 125
        local_h = int(res[2]) + int(int(resolution[1]) / 2) - 62
        self.box = Toplevel(root)
        self.box.withdraw()
        self.box.geometry(f"250x125+{local_w}+{local_h}")
        self.box.resizable(False, False)
        self.box.attributes("-topmost", True)
        self.box['bg'] = theme['bg']
        self.box.overrideredirect(1)
        self.bg = Label(self.box, width=50, height=30, bg="red")
        self.bg.place(x=0, y=0)
        self.bg_footer = Label(self.box, height=2, bg=theme['bg'])
        self.bg_footer.place(x=2, y=88, relwidth=0.985)
        self.line = Label(self.box, width=50, height=0)
        self.line.pack(side=TOP)
        self.text = Text(self.box, font=10, height=4, width=27, bg=theme['bg'], fg=theme['text_color'], relief="flat",
                         wrap=WORD)
        self.text.tag_configure("center", justify="center")
        self.text.pack(side=TOP, padx=2)
        self.entry = Entry(self.box, font=12, width=20, fg=theme['text_color'], bg=theme['entry'],
                           relief=theme['relief'], cursor=theme['cursor'])
        self.button = Button(self.box, width=15, text="Ok", fg=theme['text_color'], relief=theme['relief'],
                             bg=theme['button_bg'], activebackground=theme['button_bg_active'],
                             command=lambda: self.destroy())
        self.button.pack(side=TOP, padx=5, pady=1)
        self.button_pos = Button(self.box, width=15, text="No", fg=theme['text_color'], relief=theme['relief'],
                                 bg=theme['button_bg'], activebackground=theme['button_bg_active'],
                                 command=lambda: self.destroy())

    def showinfo(self, title, text):
        self.box.deiconify()
        self.box.grab_set()
        self.text.insert(END, text)
        self.text.tag_add("center", "1.0", "end")
        self.line.configure(bg="#1E90FF", text=title)
        self.bg.configure(bg="#1E90FF")

    def showwarning(self, title, text):
        self.box.deiconify()
        self.box.grab_set()
        self.text.insert(END, text)
        self.text.tag_add("center", "1.0", "end")
        self.line.configure(bg="#FF8C00", text=title)
        self.bg.configure(bg="#FF8C00")

    def showerror(self, title, text):
        self.box.deiconify()
        self.box.grab_set()
        self.text.insert(END, text)
        self.text.tag_add("center", "1.0", "end")
        self.line.configure(bg="#8B0000", text=title)
        self.bg.configure(bg="#8B0000")

    def askyesno(self, title, text, func, func2=None):
        self.box.deiconify()
        self.box.grab_set()
        self.text.insert(END, text)
        self.text.tag_add("center", "1.0", "end")
        self.line.configure(bg="#8B0000", text=title)
        self.bg.configure(bg="#8B0000")
        self.button.pack_forget()
        self.button.configure(text="Yes", command=lambda: (func(), self.destroy()))
        self.button.pack(side=LEFT, padx=5, pady=1)
        if func2 is not None:
            self.button_pos.configure(command=lambda: (func2(), self.destroy()))
        self.button_pos.pack(side=LEFT, padx=5, pady=1)

    def askentry(self, title, func):
        self.box.deiconify()
        self.box.grab_set()
        self.text.pack_forget()
        self.entry.pack(side=TOP, pady=25, padx=5)
        self.line.configure(bg="#8B0000", text=title)
        self.bg.configure(bg="#8B0000")
        self.button.pack_forget()
        self.button.configure(text="Go", command=lambda: (func(self.entry.get()), self.destroy()))
        self.button.pack(side=TOP, padx=5, pady=1)

    def destroy(self):
        self.box.destroy()


def folders():
    try:
        mkdir(files_dir)
    except FileExistsError:
        pass
    try:
        mkdir(files_dir + "/temp")
    except FileExistsError:
        pass
    try:
        mkdir(files_dir + "/cache")
    except FileExistsError:
        pass
    try:
        mkdir(files_dir + "/settings")
        create_theme_file()
        create_config_file()
    except FileExistsError:
        pass


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
        dump(theme_dict, file, indent=2)


def create_config_file():
    theme_dict = {}
    theme_dict.update({"theme": "0",
                       "pin1": None,
                       "pin2": None,
                       "pin3": None,
                       "update": 60,
                       "browser_path": None})
    with open(files_dir + "/settings/config.json", "w") as file:
        dump(theme_dict, file, indent=2)


def set_theme(flag=None):
    global theme
    if flag is None:
        with open(files_dir + "/settings/config.json", "r") as file:
            temp = load(file)['theme']
    else:
        temp = flag
        with open(files_dir + "/settings/config.json", "r") as file:
            tmp = load(file)
        tmp['file'] = temp
        with open(files_dir + "/settings/config.json", "w") as file:
            dump(tmp, file, indent=2)
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
                theme = load(file)
        except Exception as e:
            m_box = CustomBox()
            m_box.showerror("Custom theme error", str(e))
            exception_handler(e)
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
    import linecache
    try:
        exc_type, exc_obj, tb = exc_info()
        _frame = tb.tb_frame
        linenos = tb.tb_lineno
        filename = _frame.f_code.co_filename
        linecache.checkcache(filename)
        line = linecache.getline(filename, linenos, _frame.f_globals)
        reason = f"EXCEPTION IN ({filename}, LINE {linenos} '{line.strip()}'): {exc_obj}"
        print(f"{reason}\n")
        print(e)
    except Exception as e:
        print(e)


def backend_request(method, url, req_json=None, files=None, headers=None):
    try:
        return request(method=method, url=url, json=req_json, files=files, headers=headers)
    except Exception as e:
        exception_handler(e)


def response_handler(method, url, req_json=None, files=None, headers=None):
    global access_token, user_login, user_password
    try:
        res = backend_request(method, url, req_json, files, headers)
        if res.status_code == 200:
            return res
        elif res.status_code == 401:
            access_token = check_password(user_login, user_password)
            return backend_request(method, url, req_json, headers={"Authorization": f"Bearer {access_token}"})
        else:
            m_box = CustomBox()
            m_box.showerror("Something went wrong!", f"Response {res.status_code}")
            return None
    except Exception as e:
        exception_handler(e)


def auto_check_message():
    try:
        get_message()
    except Exception as e:
        exception_handler(e)


def check_input(password: str, log: str):
    m_box = CustomBox()
    if len(log) < 5:
        m_box.showerror("Input error", "Login length must be more than 5 characters")
        return False
    if len(password) < 8:
        m_box.showerror("Input error", 'Password does not meet the requirements')
        return False
    for i in password:
        if ord(i) < 45 or ord(i) > 122:
            m_box.showerror("Input error", "Unsupported symbols")
            return False
    for i in log:
        if ord(i) < 45 or ord(i) > 122:
            m_box.showerror("Input error", "Unsupported symbols")
            return False
    return True


# region API
def api_awake():
    global root
    root.update()
    try:
        res = backend_request(method="get", url=f"{backend_url}service/awake").json()
        res = res.split(" ")
        get_updates(float(res[0]), float(res[1]))
    except Exception as e:
        exception_handler(e)


def check_password(log, pas):
    try:
        return response_handler(method="post", url=f"{backend_url}auth/login", req_json={"login": log,
                                                                                         "password": pas}).json()
    except Exception as e:
        exception_handler(e)


def create_user(lgn, hashed_pass, mail):
    try:
        return response_handler(method="post", url=f"{backend_url}auth/register", req_json={"login": lgn,
                                                                                            "password": hashed_pass,
                                                                                            "pubkey": keys_generation(),
                                                                                            "email": mail}).json()
    except Exception as e:
        exception_handler(e)


def get_id(log):
    try:
        return response_handler(method="get", url=f"{backend_url}user/get_id?login={log}").json()
    except Exception as e:
        exception_handler(e)


def find_user(user):
    try:
        return response_handler(method="get", url=f"{backend_url}user/find?login={user}").json()
    except Exception as e:
        exception_handler(e)


def get_user_nickname(user):
    try:
        return response_handler(method="get", url=f"{backend_url}user/get_nickname?id={user}").json()
    except Exception as e:
        exception_handler(e)


def get_random_users():
    try:
        return response_handler(method="get", url=f"{backend_url}user/get_random").json()
    except Exception as e:
        exception_handler(e)


def get_pubkey(user):
    try:
        return response_handler(method="get", url=f"{backend_url}user/get_pubkey?id={user}").json()
    except Exception as e:
        exception_handler(e)


def message_send(chat_id, message, message1):
    global access_token
    try:
        return response_handler(method="post", url=f"{backend_url}message/send",
                                req_json={"destination": chat_id, "message": message, "message1": message1},
                                headers={"Authorization": f"Bearer {access_token}"}).json()
    except Exception as e:
        exception_handler(e)


def message_loop():
    global access_token
    try:
        return response_handler(method="get", url=f"{backend_url}message/loop",
                                headers={"Authorization": f"Bearer {access_token}"}).json()
    except Exception as e:
        exception_handler(e)


def message_send_chat(chat, target, message):
    global access_token
    try:
        return response_handler(method="post", url=f"{backend_url}message/send/chat",
                                req_json={"sender": chat, "destination": target, "message": message},
                                headers={"Authorization": f"Bearer {access_token}"}).json()
    except Exception as e:
        exception_handler(e)


def doc_send(file_path, chat):
    global access_token
    try:
        return response_handler(method="get",
                                url=f"{backend_url}file/shorter?url={upload_file(file_path)}&destination={chat}",
                                headers={"Authorization": f"Bearer {access_token}"}).json()
    except Exception as e:
        exception_handler(e)


def chat_send_doc(file_path, chat, user, target):
    global access_token
    try:
        return response_handler(method="get",
                                url=f"{backend_url}file/shorter/chat?url={upload_file(file_path)}&sender={chat}_{user}&"
                                    f"destination={target}", headers={"Authorization": f"Bearer {access_token}"}).json()
    except Exception as e:
        exception_handler(e)


def get_messages(cur_chat, is_chat):
    global access_token
    try:
        with open(files_dir + f"/cache/chat_{current_chat}_cache.json", "r") as file:
            max_id = load(file)['max_id']
    except FileNotFoundError:
        max_id = 0
    try:
        try:
            return response_handler(method="get", url=f"{backend_url}message/get?chat_id={cur_chat}&is_chat={is_chat}&"
                                                      f"max_id={max_id}",
                                    headers={"Authorization": f"Bearer {access_token}"}).json()
        except AttributeError:
            return None
    except Exception as e:
        exception_handler(e)


def regenerate_keys():
    button_regenerate.update()
    global user_login, user_password, access_token
    try:
        m_box = CustomBox()
        res = response_handler(method="put", url=f"{backend_url}user/update_pubkey",
                               req_json={'pubkey': keys_generation()},
                               headers={"Authorization": f"Bearer {access_token}"}).json()
        if res:
            m_box.showinfo("Success", "Regeneration successful!")
        else:
            m_box.showerror("Failed", "Regeneration failed!")
    except Exception as e:
        exception_handler(e)


def chat_create(name):
    global access_token
    try:
        return response_handler(method="post", url=f"{backend_url}chat/create", req_json={"name": name},
                                headers={"Authorization": f"Bearer {access_token}"}).json()
    except Exception as e:
        exception_handler(e)


def get_chat_id(name: str):
    try:
        return response_handler(method="get", url=f"{backend_url}chat/get_id?name={name}").json()
    except Exception as e:
        exception_handler(e)


def get_chat_name(group_id: str):
    try:
        return response_handler(method="get", url=f"{backend_url}chat/get_name?group_id={group_id}").json()
    except Exception as e:
        exception_handler(e)


def get_user_groups(user: int):
    try:
        return response_handler(method="get", url=f"{backend_url}user/get_groups?user_id={user}").json()
    except Exception as e:
        exception_handler(e)


def get_chat_users(group_id: str):
    global access_token
    try:
        return response_handler(method="get", url=f"{backend_url}chat/get_users?group_id={group_id}",
                                headers={"Authorization": f"Bearer {access_token}"}).json()
    except Exception as e:
        exception_handler(e)


def upload_file(file_path: str):
    try:
        return response_handler(method="post", url=f"{backend_url}file/upload",
                                files={"file": open(file_path, "rb")}).json()
    except Exception as e:
        exception_handler(e)


def send_recovery(user: str):
    try:
        return response_handler(method="post", url=f"{backend_url}recovery/send?login={user}").json()
    except Exception as e:
        exception_handler(e)


def validate_recovery(local_code: str, lgn: str, hashed_pass=None):
    try:
        return response_handler(method="post", url=f"{backend_url}recovery/validate",
                                req_json={"code": local_code, "login": lgn, "password": hashed_pass}).json()
    except Exception as e:
        exception_handler(e)


def update_password(old_pass: str, new_pass: str):
    global access_token
    try:
        return response_handler(method="put", url=f"{backend_url}user/update_password",
                                req_json={"old_password": old_pass, "new_password": new_pass},
                                headers={"Authorization": f"Bearer {access_token}"}).json()
    except Exception as e:
        exception_handler(e)


def user_invite(name: str, user: int):
    global access_token
    try:
        return response_handler(method="post", url=f"{backend_url}chat/invite", req_json={"name": name, "user": user},
                                headers={"Authorization": f"Bearer {access_token}"}).json()
    except Exception as e:
        exception_handler(e)


def user_kick(name: str, user: int):
    global access_token
    try:
        return response_handler(method="post", url=f"{backend_url}chat/kick", req_json={"name": name, "user": user},
                                headers={"Authorization": f"Bearer {access_token}"}).json()
    except Exception as e:
        exception_handler(e)


def remove_data_request():
    global access_token
    try:
        return response_handler(method="delete", url=f"{backend_url}user/remove",
                                headers={"Authorization": f"Bearer {access_token}"}).json()
    except Exception as e:
        exception_handler(e)
# endregion


def auto_login():
    try:
        lgn = get_password("datachat", "login")
        psw = get_password("datachat", "password")
        if lgn is not None and psw is not None:
            entry_log.insert(0, lgn)
            entry_pass.insert(0, psw)
            remember_var.set(1)
            login()
    except Exception as e:
        exception_handler(e)


def clear_auto_login():
    try:
        delete_password("datachat", "login")
    except errors.PasswordDeleteError:
        pass
    try:
        delete_password("datachat", "password")
    except errors.PasswordDeleteError:
        pass


def fill_auto_login_file(lgn: str, psw: str):
    set_password("datachat", "login", lgn)
    set_password("datachat", "password", psw)


def regenerate_encryption_keys():
    m_box = CustomBox()
    m_box.askyesno("Regenerate keys", "Are you sure? You will lose access to all messages", regenerate_keys)


def delete_account():
    m_box = CustomBox()
    m_box.askyesno("Delete account", "Are you sure? You will lose access to your account", remove_data_request)


# noinspection PyUnusedLocal
def login(*args):
    global user_login, user_id, user_password, access_token
    label_loading.place(x=60, y=80)
    button_login.update()
    try:
        m_box = CustomBox()
        if len(entry_log.get()) == 0 or len(entry_pass.get()) == 0:
            m_box.showerror("Input error", "Fill all input fields")
            label_loading.place_forget()
            return
        res = check_password(entry_log.get(), entry_pass.get())
        user_password = entry_pass.get()
        if res is None:
            m_box.showerror("Input error", "User not found")
            label_loading.place_forget()
            return
        elif not res:
            m_box = CustomBox()
            m_box.askyesno("Input error", "Wrong password, recover?", pass_code)
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
        local_chats = response_handler(method="get", url=f"{backend_url}chat/get_all",
                                       headers={"Authorization": f"Bearer {access_token}"}).json()
        for i in range(local_chats['count']):
            try:
                build(local_chats[f'item_{i}'])
            except KeyError:
                break
        hide_auth_menu()
        label_loading.place_forget()
        qr = make(private_key)
        qr.save(files_dir + "/temp/QR.png")
        qr = Image.open(files_dir + "/temp/QR.png")
        width = int(qr.size[0] / 2)
        height = int(qr.size[1] / 2)
        img = qr.resize((width, height), Image.ANTIALIAS)
        img.save(files_dir + "/temp/QR.png")
        _qr = PhotoImage(file=files_dir + "/temp/QR.png")
        label_qr = Label(main1_frame, image=_qr)
        label_qr.image = _qr
        # label_qr.pack(side=RIGHT, anchor=SE) # задумка на будущее
        remove(files_dir + "/temp/QR.png")
        menu_navigation("chat")
    except Exception as e:
        label_loading.place_forget()
        exception_handler(e)


def show_reg_frame():
    root.geometry("200x215+{}+{}".format(w, h))
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
    root.geometry("200x200+{}+{}".format(w, h))
    check_remember.pack(side=TOP, anchor=S)
    button_login.pack(side=LEFT, pady=3, anchor=CENTER)
    button_reg_m.pack(side=RIGHT, pady=3, anchor=CENTER)


def register():
    button_reg.update()
    try:
        lgn, psw = entry_log.get(), entry_pass.get()
        mail = entry_email.get()
        m_box = CustomBox()
        if len(lgn) == 0 or len(psw) == 0:
            m_box.showerror("Input error", "Fill all input fields")
            return
        if len(mail) <= 8 or " " in mail or "@" not in mail or "." not in mail:
            m_box.showerror("Input error", "Enter valid email")
            return
        if not check_input(psw, lgn):
            return
        hashed_pass = hashpw(psw.encode("utf-8"), gensalt())
        hashed_pass = str(hashed_pass)[2:-1]
        res = create_user(lgn, hashed_pass, mail)
        if res is True:
            m_box.showinfo("Success", "Register success!")
        elif res is None:
            m_box.showerror("Input error", "Can't register this login!")
        else:
            m_box.showerror("Input error", "User already register")
    except Exception as e:
        exception_handler(e)


def hide_auth_menu():
    global w, h, empty_top_frame, button_close
    w -= 200
    auth_frame.pack_forget()
    root.geometry("1100x525+{}+{}".format(w, h))
    entry_msg.focus_set()
    empty_top_frame.pack_forget()
    button_close.pack_forget()
    button_chat.pack(side=LEFT, anchor=W)
    button_info.pack(side=LEFT, padx=5, anchor=W)
    button_settings.pack(side=LEFT, anchor=W)
    button_logout.pack(side=LEFT, padx=5, anchor=W)
    empty_top_frame.pack(side=LEFT, padx=470, anchor=W)
    button_close.pack(side=RIGHT, anchor=E)
    menu_frame.pack(side=LEFT, pady=5, anchor=N)
    main_frame.pack(side=LEFT, anchor=CENTER)


def menu_navigation(menu: str):
    global current_chat, chats, spacing, spacing_2, private_key, user_id
    if menu == "chat":
        button_chat.update()
        for key in chats:
            chats[key].pack_forget()
        button_back.pack_forget()
        button_chat.configure(bg=theme['button_bg_positive'])
        button_info.configure(bg=theme['button_bg'])
        button_settings.configure(bg=theme['button_bg'])
        main1_frame.pack_forget()
        settings_frame.pack_forget()
        group_frame.pack_forget()
        main_frame.pack(side=LEFT, anchor=CENTER)
        canvas.delete(0.0, END)
        current_chat = "-1"
        label_chat_id.configure(text="Current chat with: ")
        spacing, spacing_2 = 0, 0
        button_send.configure(state='disabled')
        button_img.configure(state='disabled')
        canvas.delete(0.0, END)
    elif menu == "set":
        button_settings.update()
        button_chat.configure(bg=theme['button_bg'])
        button_info.configure(bg=theme['button_bg'])
        button_settings.configure(bg=theme['button_bg_positive'])
        main_frame.pack_forget()
        main1_frame.pack_forget()
        group_frame.pack_forget()
        settings_frame.pack(side=LEFT, anchor=N)
    elif menu == "info":
        button_info.update()
        button_chat.configure(bg=theme['button_bg'])
        button_info.configure(bg=theme['button_bg_positive'])
        button_settings.configure(bg=theme['button_bg'])
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
                canvas_users.insert(parent='', index=END, values=(user['id'], user['login'], date), tags=("users_tag",))
            except KeyError:
                break


def send_message():
    global user_id, current_chat
    button_send.update()
    try:
        msg = entry_msg.get()
        m_box = CustomBox()
        if len(msg) == 0:
            m_box.showerror("Input error", "Fill all input fields")
            return
        for i in msg:
            if ord(i) < 32 or ord(i) > 1366:
                m_box.showerror("Input error", "Unsupported symbols")
                return
        encrypt_msg = encrypt_message(msg.encode("utf-8"), get_pubkey(current_chat))
        encrypt_msg1 = encrypt_message(msg.encode("utf-8"), get_pubkey(user_id))
        message_send(current_chat, encrypt_msg, encrypt_msg1)
        entry_msg.delete(0, END)
        get_message()
    except Exception as e:
        exception_handler(e)


def send_doc():
    button_img.update()
    global current_chat
    try:
        local_path = filedialog.askopenfilename(filetypes=[("All files", "*.*")])
        if len(local_path) == 0:
            return
        doc_send(local_path, current_chat)
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
    res = get_cache_messages()
    try:
        canvas.delete(0.0, END)
        chat_nick = 0
        for i in range(res['count']):
            try:
                message = res[f'item_{i}']
                if chat_nick == 0 and message['from_id'] != user_login:
                    chat_nick = message['from_id']
                nick = user_login if message['from_id'] == user_login else chat_nick
                if message['from_id'] == user_login:
                    decrypt_msg = decrypt_message(int2bytes(message['message1']))
                else:
                    decrypt_msg = decrypt_message(int2bytes(message['message']))
                date = datetime.strptime(message['date'], "%Y-%m-%dT%H:%M:%S")
                canvas.insert(END, f"{str(date + utc_diff)[2:]} {nick}: ")
                if "chat-b4ckend.herokuapp.com/file/get/file_" not in decrypt_msg:
                    canvas.insert(END, f"{decrypt_msg}\n")
                else:
                    canvas.insert(END, f"{decrypt_msg}\n", "url_tag")
                canvas.update()
            except KeyError:
                break
    except Exception as e:
        exception_handler(e)


def encrypt_message(msg: bytes, pubkey):
    try:
        pubkey = pubkey.split(", ")
        pubkey = PublicKey(int(pubkey[0]), int(pubkey[1]))
        encrypted_message = encrypt(msg, pubkey)
        return bytes2int(encrypted_message)
    except Exception as e:
        exception_handler(e)


def decrypt_message(msg: bytes):
    global private_key
    try:
        decrypted_message = decrypt(msg, private_key)
        return decrypted_message.decode("utf-8")
    except Exception as e:
        exception_handler(e)
        return None


# noinspection PyUnusedLocal
def login_handler(*args):
    if len(entry_log.get()) == 0:
        m_box = CustomBox()
        m_box.showerror("Input error", "Fill all input fields")
        return
    elif len(entry_pass.get()) != 0:
        login()
    else:
        entry_pass.focus_set()


# noinspection PyUnusedLocal
def send_message_handler(*args):
    global current_chat
    if str(root.focus_get()) == ".!labelframe2.!entry":
        if len(entry_msg.get()) != 0:
            if current_chat[0] != "g":
                send_message()
            else:
                send_chat_message()
        else:
            entry_msg.focus_set()


# noinspection PyUnusedLocal
def change_pass_handler(*args):
    m_box = CustomBox()
    if str(root.focus_get()) == ".!labelframe3.!labelframe3.!labelframe.!entry":
        if len(entry_old_pass.get()) != 0:
            entry_new_pass.focus_set()
            return
        elif len(entry_old_pass.get()) != 0 and len(entry_new_pass.get()) != 0:
            change_password()
            return
    elif str(root.focus_get()) == ".!labelframe3.!labelframe3.!labelframe2.!entry":
        if len(entry_new_pass.get()) == 0:
            m_box.showerror("Input error", "Fill all input fields")
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
        (pubkey, privkey) = newkeys(1024)
        pubkey = str(pubkey)[10:-1]
        set_password("datachat", "private_key", privkey.save_pkcs1().decode("ascii"))
        private_key = privkey
        return pubkey
    except Exception as e:
        exception_handler(e)


def get_private_key():
    try:
        global private_key
        private_key = PrivateKey.load_pkcs1(get_password("datachat", "private_key").encode("utf-8"))
    except Exception as e:
        exception_handler(e)


def create_chat():
    global user_id
    button_c_chat.update()
    try:
        name = entry_chat.get()
        m_box = CustomBox()
        if len(name) < 5:
            m_box.showerror("Input error", "Name length must be more than 5 characters")
            return
        if name[-3:] != "_gr":
            m_box.showerror("Input error", "Name must contain '_gr' in the end")
            return
        for i in name:
            if ord(i) < 45 or ord(i) > 122:
                m_box.showerror("Input error", 'Unsupported symbols')
                return
        res = chat_create(name)
        if res:
            m_box.showinfo("Success", "Chat created")
            return
        elif res is None:
            m_box.showerror("Name error", "Name exists")
            return
        else:
            m_box.showerror("Unknown error", "oooops!")
    except Exception as e:
        exception_handler(e)


def send_chat_message():
    global user_id, current_chat
    button_send.update()
    message = entry_msg.get()
    try:
        m_box = CustomBox()
        if len(message) == 0:
            m_box.showerror("Input error", "Fill all input fields")
            return
        for i in get_chat_users(current_chat):
            message_send_chat(current_chat, i[0], encrypt_message(message.encode("utf-8"), get_pubkey(i[0])))
            entry_msg.delete(0, END)
        get_chat_message()
    except Exception as e:
        exception_handler(e)


def send_chat_doc():
    global user_id, current_chat
    button_img.update()
    try:
        local_path = filedialog.askopenfilename(filetypes=[("All files", "*.*")])
        if len(local_path) == 0:
            return
        for i in get_chat_users(current_chat):
            chat_send_doc(local_path, current_chat, user_id, i[0])
        get_chat_message()
    except Exception as e:
        exception_handler(e)


def get_chat_message():
    global current_chat
    try:
        button_refresh.update()
    except NotImplementedError:
        pass
    res = get_messages(current_chat, 1)
    if res is None:
        return
    cache_messages(res)
    res = get_cache_messages()
    try:
        canvas.delete(0.0, END)
        for i in range(res['count']):
            try:
                message = res[f'item_{i}']
                decrypt_msg = decrypt_message(int2bytes(message['message']))
                date = datetime.strptime(message['date'], "%Y-%m-%dT%H:%M:%S")
                canvas.insert(END, f"{str(date + utc_diff)[2:]} {message['from_id']}: ")
                if "chat-b4ckend.herokuapp.com/file/get/file_" not in decrypt_msg:
                    canvas.insert(END, f"{decrypt_msg}\n")
                else:
                    canvas.insert(END, f"{decrypt_msg}\n", "url_tag")
                canvas.update()
            except KeyError:
                break
    except Exception as e:
        exception_handler(e)


def invite_to_group():
    global user_id
    button_invite.update()
    inv_user = entry_inv_id.get()
    inv_group = entry_gr_to_inv.get()
    m_box = CustomBox()
    if len(inv_user) == 0 and len(inv_group) == 0:
        m_box.showerror("Input error", "Entries length must be more than 0 characters")
        return
    try:
        name = get_chat_name(inv_group)
        groups = get_user_groups(inv_user)
        if name in groups:
            m_box.showerror("Input error", "User already in group")
            return
        if not user_invite(name, int(inv_user)):
            m_box.showerror("Access error", "You are not chat's owner")
            return
        m_box.showinfo("Success", "Success")
    except Exception as e:
        exception_handler(e)


def kick_from_group():
    global user_id
    button_kick.update()
    kick_user = entry_kick_id.get()
    kick_group = entry_gr_to_kick.get()
    m_box = CustomBox()
    if len(kick_user) == 0 and len(kick_group) == 0:
        m_box.showerror("Input error", "Entries length must be more than 0 characters")
        return
    try:
        name = get_chat_name(kick_group)
        groups = get_user_groups(kick_user)
        if name not in groups:
            m_box.showerror("Input error", "User is not in group")
            return
        if not user_kick(name, int(kick_user)):
            m_box.showerror("Access error", "You are not chat's owner")
            return
        m_box.showinfo("Success", "Success")
    except Exception as e:
        exception_handler(e)


def logout():
    global w, h, chat_labels
    w += 200
    menu_navigation("chat")
    button_chat.pack_forget()
    button_info.pack_forget()
    button_settings.pack_forget()
    button_logout.pack_forget()
    menu_frame.pack_forget()
    main_frame.pack_forget()
    empty_top_frame.pack_forget()
    empty_top_frame.pack(side=LEFT, padx=80, anchor=W)
    button_close.pack(side=RIGHT, anchor=E)
    root.geometry("200x200+{}+{}".format(w, h))
    for i in chat_labels:
        i[0].pack_forget()
    chat_labels = []
    entry_log.focus_set()
    auth_frame.pack(side=TOP, anchor=CENTER)


def recovery_menu():
    global w, h, code
    try:
        auth_frame.pack_forget()
        root.geometry("200x135+{}+{}".format(w, h))
        recovery_frame.pack(side=TOP, anchor=CENTER)
    except Exception as e:
        exception_handler(e)


def new_pass_menu():
    global w, h, user_login, code
    try:
        m_box = CustomBox()
        code = entry_code.get()
        if not validate_recovery(entry_code.get(), entry_log.get()):
            m_box.showerror("Input error", "Incorrect code")
            return
        recovery_frame.pack_forget()
        root.geometry("200x165+{}+{}".format(w, h))
        new_pass_frame.pack(side=TOP, anchor=CENTER)
    except Exception as e:
        exception_handler(e)


def change_password():
    global user_login
    button_pass_font.update()
    try:
        m_box = CustomBox()
        if len(entry_old_pass.get()) == 0 or len(entry_new_pass.get()):
            m_box.showerror("Input error!", "Empty input field!")
            return
        hashed_pass = hashpw(entry_new_pass.get().encode("utf-8"), gensalt())
        hashed_pass = str(hashed_pass)[2:-1]
        res = update_password(entry_old_pass.get(), hashed_pass)
        if res:
            m_box.showinfo("Success", "Password has been changed")
            fill_auto_login_file(user_login, entry_new_pass.get())
            return
        elif res is None:
            m_box.showerror("Input error", "User not found")
            return
        else:
            m_box.showerror("Input error", "Current password is wrong")
    except Exception as e:
        exception_handler(e)


def set_new_pass():
    global user_login, email, code
    button_code.update()
    user_login = entry_log.get()
    try:
        if check_input(entry_new_p2.get(), entry_new_p.get()):
            if entry_new_p.get() == entry_new_p2.get():
                m_box = CustomBox()
                hashed_pass = hashpw(entry_new_p.get().encode("utf-8"), gensalt())
                hashed_pass = str(hashed_pass)[2:-1]
                res = validate_recovery(code, user_login, hashed_pass)
                if res:
                    m_box.showinfo("Success", "Password has been changed")
                    fill_auto_login_file(user_login, entry_new_p.get())
                    entry_pass.delete(0, END)
                    entry_pass.insert(0, entry_new_p.get())
                    root.geometry("200x195+{}+{}".format(w, h))
                    new_pass_frame.pack_forget()
                    auth_frame.pack(side=TOP, anchor=CENTER)
                else:
                    m_box.showerror("Failed", "Password has not been changed")
    except Exception as e:
        exception_handler(e)


def pass_code():
    try:
        m_box = CustomBox()
        res = send_recovery(entry_log.get())
        if res:
            m_box.showinfo("Recovery", "Recovery code has been sent to your email")
            recovery_menu()
            return
        elif res is None:
            m_box.showwarning("Recovery", "User not found")
            return
        else:
            m_box.showerror("Recovery", "Recovery code has not been sent")
    except Exception as e:
        exception_handler(e)


def open_chat(chat_id):
    global current_chat
    m_box = CustomBox()
    if len(chat_id) == 0 or not chat_id.isnumeric():
        current_chat = chat_id
        name = get_chat_name(current_chat)
        label_chat_id.configure(text="Current chat with: " + name)
        button_send.configure(state="normal")
        button_img.configure(state="normal")
        canvas.delete(0.0, END)
        get_chat_message()
        return
    nick = get_user_nickname(int(chat_id))
    if nick is not None:
        label_chat_id.configure(text="Current chat with: " + nick)
    else:
        m_box.showerror("Input error", "User not found")
        return
    current_chat = chat_id
    button_send.configure(state="normal")
    button_img.configure(state="normal")
    canvas.delete(0.0, END)
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
                    date = str(datetime.strptime(user['last_activity'], "%Y-%m-%dT%H:%M:%S") + utc_diff)[2:]
                except TypeError:
                    date = ""
                canvas_users.insert(parent='', index=END, values=(user['id'], user['login'], date), tags=("users_tag",))
            except KeyError:
                break
    except Exception as e:
        exception_handler(e)


def cache_messages(messages):
    global current_chat
    try:
        try:
            with open(files_dir + f"/cache/chat_{current_chat}_cache.json", "r") as file:
                json_dict = load(file)
            count = json_dict['count']
            for i in range(messages['count']):
                try:
                    message = messages[f'item_{i}']
                    json_dict.update({f'item_{i + count}': message})
                except KeyError:
                    break
            json_dict.update({'count': count + messages['count']})
            if messages['max_id'] != 0:
                json_dict.update({'max_id': messages['max_id']})
        except FileNotFoundError:
            json_dict = messages
        with open(files_dir + f"/cache/chat_{current_chat}_cache.json", "w") as file:
            dump(json_dict, file, indent=2)
    except FileNotFoundError:
        pass
    except Exception as e:
        exception_handler(e)


def get_cache_messages():
    global current_chat
    try:
        with open(files_dir + f"/cache/chat_{current_chat}_cache.json", "r") as file:
            res = load(file)
        return res
    except FileNotFoundError:
        pass
    except Exception as e:
        exception_handler(e)


def get_browser_path():
    try:
        with open(files_dir + "/settings/config.json", "r") as file:
            res = load(file)['browser_path']
        if res is None:
            res = ""
        return res
    except Exception as e:
        exception_handler(e)


def save_browser_path():
    try:
        m_box = CustomBox()
        if len(entry_path.get()) == 0:
            m_box.showerror("Input error!", "Empty path")
            return
        if entry_path.get()[-4:] != ".exe":
            m_box.showerror("Input error!", "Not .exe file")
            return
        with open(files_dir + "/settings/config.json", "r") as file:
            json_file = load(file)
        json_file['browser_path'] = entry_path.get()
        with open(files_dir + "/settings/config.json", "w") as file:
            dump(json_file, file, indent=2)
        m_box.showinfo("Success!", "Browser path saved")
    except Exception as e:
        exception_handler(e)


def save_theme():
    global theme_var
    m_box = CustomBox()
    with open(files_dir + "/settings/config.json", "r") as file:
        json_file = load(file)
    json_file['theme'] = theme_var.get()
    with open(files_dir + "/settings/config.json", "w") as file:
        dump(json_file, file, indent=2)
    if theme_var.get() == 2:
        if not path.exists(files_dir + "/settings/theme.json"):
            create_theme_file()
        theme_editor()
    else:
        m_box.showinfo("Success!", "Theme will be changed on next launch!")


def theme_editor():
    global relief, frames_relief, cursors
    with open(files_dir + "/settings/theme.json", "r") as file:
        temp = load(file)
    relief.set(temp['relief'])
    label_wid_box.configure(relief=temp['relief'])
    frames_relief.set(temp['frame_relief'])
    label_frame_box.configure(relief=temp['frame_relief'])
    cursors.set(temp['cursor'])
    theme_editor_window.deiconify()
    theme_editor_window.grab_set()
    entry_text.delete(0, END)
    entry_text.insert(0, temp['text_color'])
    label_text_box.configure(bg=temp['text_color'])
    entry_entry.delete(0, END)
    entry_entry.insert(0, temp['entry'])
    label_entry_box.configure(bg=temp['entry'])
    entry_bg.delete(0, END)
    entry_bg.insert(0, temp['bg'])
    label_bg_box.configure(bg=temp['bg'], relief=GROOVE)
    entry_sel_bg.delete(0, END)
    entry_sel_bg.insert(0, temp['select_bg'])
    label_sel_box.configure(bg=temp['select_bg'])
    entry_font.delete(0, END)
    entry_font.insert(0, temp['font_main'])
    try:
        font = temp['font_main'].split()
        font.pop(len(font) - 1)
        font = Font(family=" ".join(font), size=10)
    except Exception as e:
        exception_handler(e)
        font = Font(size=10)
    label_font_box.configure(text="Aa", font=font)
    entry_font_u.delete(0, END)
    entry_font_u.insert(0, temp['font_users'])
    try:
        font = temp['font_main'].split()
        font.pop(len(font) - 1)
        font = Font(family=" ".join(font), size=10)
    except Exception as e:
        exception_handler(e)
        font = Font(size=10)
    label_users_box.configure(text="Aa", font=font)
    entry_font_b.delete(0, END)
    entry_font_b.insert(0, temp['button_font'])
    try:
        font = temp['font_main'].split()
        font.pop(len(font) - 1)
        font = Font(family=" ".join(font), size=10)
    except Exception as e:
        exception_handler(e)
        font = Font(size=10)
    label_font_b_box.configure(text="Aa", font=font)
    entry_bg_b.delete(0, END)
    entry_bg_b.insert(0, temp['button_bg'])
    label_bg_b_box.configure(bg=temp['button_bg'])
    entry_bg_b_pos.delete(0, END)
    entry_bg_b_pos.insert(0, temp['button_bg_positive'])
    label_pos_box.configure(bg=temp['button_bg_positive'])
    entry_bg_b_neg.delete(0, END)
    entry_bg_b_neg.insert(0, temp['button_bg_negative'])
    label_neg_box.configure(bg=temp['button_bg_negative'])
    entry_b_act.delete(0, END)
    entry_b_act.insert(0, temp['button_bg_active'])
    label_act_box.configure(bg=temp['button_bg_active'])


def theme_editor_save():
    theme_dict = {}
    m_box = CustomBox()
    try:
        label_text_box.configure(bg=entry_text.get())
        label_entry_box.configure(bg=entry_entry.get())
        label_wid_box.configure(relief=relief.get())
        label_frame_box.configure(relief=frames_relief.get())
        label_bg_box.configure(bg=entry_bg.get())
        label_sel_box.configure(bg=entry_sel_bg.get())
        label_bg_b_box.configure(bg=entry_bg_b.get())
        label_pos_box.configure(bg=entry_bg_b_pos.get())
        label_neg_box.configure(bg=entry_bg_b_neg.get())
        label_act_box.configure(bg=entry_b_act.get())
    except Exception as e:
        exception_handler(e)
    theme_editor_window.update()
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
        dump(theme_dict, file, indent=2)
    theme_editor_window.withdraw()
    root.grab_set()
    m_box.showinfo("Success!", "Theme will be changed on next launch!")


def export_program_data():
    global user_password
    import pyminizip
    try:
        files, paths = [], []
        destination = filedialog.askdirectory()
        if destination == "":
            return
        with open(files_dir + "/settings/key.json", "w") as file:
            dump({'key': get_password("datachat", "private_key")}, file)
        for i in listdir(files_dir + "/settings"):
            files.append(files_dir + "/settings/" + i)
        for i in listdir(files_dir + "/cache"):
            files.append(files_dir + "/cache/" + i)
        for i in range(len(files)):
            paths.append("\\")
        pyminizip.compress_multiple(files, paths, destination + "/export.zip", user_password, 3)
    except Exception as e:
        exception_handler(e)
    finally:
        remove(files_dir + "/settings/key.json")


def import_program_data():
    global user_password
    import pyminizip
    try:
        local_path = filedialog.askopenfilename(filetypes=[("Zip files", "*.zip")])
        if local_path == "":
            return
        pyminizip.uncompress(local_path, user_password, files_dir + "/temp", 0)
        with open(files_dir + "/temp/key.json", "r") as file:
            key = load(file)["key"]
        set_password("datachat", "private_key", key)
        replace(files_dir + "/temp/theme.json", files_dir + "/settings/theme.json")
        replace(files_dir + "/temp/config.json", files_dir + "/settings/config.json")
        remove(files_dir + "/temp/key.json")
        for i in listdir(files_dir + "/temp"):
            replace(files_dir + "/temp/" + i, files_dir + "/cache/" + i)
    except Exception as e:
        exception_handler(e)


def open_link(event):
    try:
        index = event.widget.index("@%s,%s" % (event.x, event.y))
        tag_indices = list(event.widget.tag_ranges('url_tag'))
        for start, end in zip(tag_indices[0::2], tag_indices[1::2]):
            if event.widget.compare(start, '<=', index) and event.widget.compare(index, '<', end):
                import webbrowser as web
                with open(files_dir + "/settings/config.json", "r") as file:
                    tmp = load(file)['browser_path']
                if tmp is not None:
                    web.register("browser", None, web.BackgroundBrowser(tmp))
                    web.get(using="browser").open_new_tab(event.widget.get(start, end))
                else:
                    web.open(event.widget.get(start, end), new=0)
    except TclError:
        pass
    except Exception as e:
        exception_handler(e)


def get_updates(app_version, old_version):
    global app_ver, root
    try:
        root.update()
        print(f"Current app is up to date: {app_ver >= app_version}\nOld app: {old_version}")
        if old_version >= app_ver:
            print("too old version")
            m_box = CustomBox()
            m_box.askyesno("Need update", "Your app version is out of date\nVisit the download page?",
                           open_download_page, on_closing)
        elif app_version > app_ver:
            print("old version")
            m_box = CustomBox()
            m_box.askyesno("New app version", "New app version is now available\nVisit the download page?",
                           open_download_page)
    except Exception as e:
        exception_handler(e)


def open_download_page():
    try:
        import webbrowser as web
        with open(files_dir + "/settings/config.json", "r") as file:
            tmp = load(file)['browser_path']
        if tmp is not None:
            web.register("browser", None, web.BackgroundBrowser(tmp))
            web.get(using="browser").open_new_tab("https://github.com/Delivery-Klad/chat_desktop/releases")
        else:
            web.open("https://github.com/Delivery-Klad/chat_desktop/releases", new=0)
    except Exception as e:
        exception_handler(e)


def get_update_time():
    global time_to_check
    with open(files_dir + "/settings/config.json", "r") as file:
        time_to_check = load(file)['update']
    if int(time_to_check) == -1:
        label_check2.configure(text="Never")
    else:
        label_check2.configure(text=f"{time_to_check} Sec")
    label_check2.update()


def auto_check():
    global time_to_check
    m_box = CustomBox()
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
    m_box.showinfo("Success!", "Notifications will be changed on next launch!")
    with open(files_dir + "/settings/config.json", "r") as file:
        json_file = load(file)
    json_file['update'] = str(time_to_check)
    with open(files_dir + "/settings/config.json", "w") as file:
        dump(json_file, file, indent=2)


def loop_msg_func():
    global time_to_check
    if time_to_check == -1:
        return
    print('check')
    try:
        if access_token == '':
            return
        res = message_loop()
        if res is not None:
            m_box = CustomBox()
            m_box.showinfo("New Messages!", f"You have new messages in chats: {res}")
        if current_chat != "-1":
            if current_chat[0] != "g":
                get_message()
            else:
                get_chat_message()
        root.after(int(time_to_check) * 1000, loop_msg_func)
    except Exception as e:
        exception_handler(e)


def build(i):
    print(i)
    global chat_labels
    name = i['username']
    if name[-3:] == "_gr":
        name = name[:-3] + " (Group)"
    while len(name) < 20:
        name += " "
    message = decrypt_message(int2bytes(i['message']))[:20]
    while len(message) < 20:
        message += " "
    chat_label = Label(menu_frame.scrollable_frame, font=theme['font_main'], bg="#606060", width=25, height=2,
                       fg=theme['text_color'], text=f"{name}\n{' ' * 6}{message}", justify=LEFT,
                       anchor=NW)
    chat_label.pack(side=TOP, anchor=N, pady=2, fill=BOTH)
    chat_label.bind("<Button-1>", lambda e: (menu_navigation("chat"), open_chat(i['user_id'])))
    chat_labels.append([chat_label, i['user_id']])


def start_chat():
    m_box = CustomBox()
    m_box.askentry("Enter user id", open_chat)


def send():
    global current_chat
    if current_chat[0] != "g":
        send_message()
    else:
        send_chat_message()


def send_document():
    global current_chat
    if current_chat[0] != "g":
        send_doc()
    else:
        send_chat_doc()


def get_all_messages():
    global current_chat
    if current_chat[0] != "g":
        get_message()
    else:
        get_chat_message()


def mouse_down(event):
    global x, y
    x, y = event.x, event.y


def mouse_up(event):
    global x, y
    print(f"{event.x} {event.y}")
    x, y = None, None


def mouse_drag(event):
    global x, y
    try:
        x0 = root.winfo_x() + event.x - x
        y0 = root.winfo_y() + event.y - y
        root.geometry("+%s+%s" % (x0, y0))
    except Exception as e:
        print(e)


def refresh_token():
    global access_token
    print("refresh")
    access_token = response_handler(method="put", url=f"{backend_url}auth/refresh",
                                    headers={"Authorization": f"Bearer {access_token}"}).json()
    root.after(570000, refresh_token)


def on_closing():
    root.destroy()
    exit(0)


# region startup config
folders()
set_theme()
# endregion
"""m = Menu(root)
root.config(menu=m)
fm = Menu(m)
m.add_cascade(label="File", menu=fm)
fmm = Menu(fm)
fm.add_cascade(label="Export", menu=fmm)"""
# region Style
style = Style()
style.theme_use("clam")
style.configure("t_style.Heading", background=theme['entry'], relief=theme['relief'], font=theme['font_users'])
style.configure("t_style", highlightthickness=0, background=theme['entry'], bd=0, font=theme['font_users'])
style.layout("t_style", [("t_style.treearea", {})])
style.configure("Vertical.TScrollbar", background=theme['entry'], bordercolor=theme['bg'], arrowcolor="white",
                darkcolor=theme['bg'], lightcolor=theme['bg'], troughcolor=theme['bg'], gripcount=0)
# endregion
# region auth
test = LabelFrame(root, width=1097, height=31, relief=FLAT, bg="red")
test.place(x=1, y=1)
top_frame = LabelFrame(root, width=200, height=25, relief=FLAT, bg=theme['bg'])
top_frame.pack(side=TOP, pady=1, anchor=CENTER)
top_frame.bind('<ButtonPress-1>', mouse_down)
top_frame.bind('<B1-Motion>', mouse_drag)
top_frame.bind('<ButtonRelease-1>', mouse_up)
empty_top_frame = Label(top_frame, text=" ", relief=theme['relief'], bg=theme['bg'], width=1)
empty_top_frame.pack(side=LEFT, padx=80, anchor=W)
button_close = Button(top_frame, text="✖", activebackground=theme['bg'], relief=theme['relief'],
                      bg=theme['bg'], width=2, command=lambda: on_closing())
button_close.pack(side=RIGHT, anchor=E)
auth_frame = LabelFrame(root, width=200, height=130, relief=FLAT, bg=theme['bg'])
auth_frame.pack(side=TOP, anchor=CENTER)
label_user = Label(auth_frame, font=theme['font_main'], text="Username:", bg=theme['bg'],
                   fg=theme['text_color'], width=19, anchor=W)
label_user.pack(side=TOP, anchor=S)
entry_log = Entry(auth_frame, font=12, width=20, fg=theme['text_color'], bg=theme['entry'], relief=theme['relief'],
                  cursor=theme['cursor'])
entry_log.bind("<Return>", login_handler)
entry_log.pack(side=TOP)
label_password = Label(auth_frame, font=theme['font_main'], text="Password:", bg=theme['bg'],
                       fg=theme['text_color'], width=19, anchor=W)
label_password.pack(side=TOP, anchor=S)
entry_pass = Entry(auth_frame, font=12, width=20, fg=theme['text_color'], bg=theme['entry'], relief=theme['relief'],
                   cursor=theme['cursor'], show='•')
entry_pass.bind("<Return>", login)
entry_pass.pack(side=TOP)
check_remember = Checkbutton(auth_frame, font=theme['font_main'], fg=theme['text_color'], bg=theme['bg'],
                             text="Remember me", activebackground=theme['bg'], selectcolor=theme['bg'],
                             variable=remember_var)
check_remember.pack(side=TOP, anchor=S)
button_login = Button(auth_frame, text="LOGIN", activebackground=theme['button_bg_active'], relief=theme['relief'],
                      bg=theme['button_bg_positive'], width=11, command=lambda: login(), font=theme['button_font'])
button_login.pack(side=LEFT, pady=3, anchor=CENTER)
button_reg_m = Button(auth_frame, text="REGISTER", activebackground=theme['button_bg_active'],
                      relief=theme['relief'],
                      bg=theme['button_bg_positive'], width=11, command=lambda: show_reg_frame(),
                      font=theme['button_font'])
button_reg_m.pack(side=RIGHT, pady=3, anchor=CENTER)
button_reg = Button(auth_frame, text="REGISTER", activebackground=theme['button_bg_active'], relief=theme['relief'],
                    bg=theme['button_bg_positive'], width=11, command=lambda: register(), font=theme['button_font'])
button_login_b = Button(auth_frame, text="BACK", activebackground=theme['button_bg_active'], relief=theme['relief'],
                        bg=theme['button_bg_positive'], width=11, command=lambda: back_to_login(),
                        font=theme['button_font'])
# endregion
# region reg
recovery_frame = LabelFrame(root, width=200, height=130, relief=FLAT, bg=theme['bg'])
label_code = Label(recovery_frame, font=theme['font_main'], text="Code:", fg=theme['text_color'], bg=theme['bg'],
                   width=19, anchor=W)
label_code.pack(side=TOP, anchor=S)
entry_code = Entry(recovery_frame, font=12, width=20, fg=theme['text_color'], bg=theme['entry'],
                   relief=theme['relief'], cursor=theme['cursor'])
entry_code.pack(side=TOP)
button_code = Button(recovery_frame, text="SEND", activebackground=theme['button_bg_active'], relief=theme['relief'],
                     bg=theme['button_bg_positive'], width=11, command=lambda: new_pass_menu(),
                     font=theme['button_font'])
button_code.pack(side=RIGHT, pady=3, anchor=CENTER)
# endregion
# region new pass
new_pass_frame = LabelFrame(root, width=200, height=130, relief=FLAT, bg=theme['bg'])
label_code = Label(new_pass_frame, font=theme['font_main'], text="New Password:", fg=theme['text_color'],
                   bg=theme['bg'], width=19, anchor=W)
label_code.pack(side=TOP, anchor=S)
entry_new_p = Entry(new_pass_frame, font=12, width=20, fg=theme['text_color'], bg=theme['entry'],
                    cursor=theme['cursor'], relief=theme['relief'], show='•')
entry_new_p.pack(side=TOP)
label_code2 = Label(new_pass_frame, font=theme['font_main'], text="Repeat Password:", fg=theme['text_color'],
                    bg=theme['bg'], width=19, anchor=W)
label_code2.pack(side=TOP, anchor=S)
entry_new_p2 = Entry(new_pass_frame, font=12, width=20, fg=theme['text_color'], bg=theme['entry'],
                     cursor=theme['cursor'], relief=theme['relief'], show='•')
entry_new_p2.pack(side=TOP)
button_code = Button(new_pass_frame, text="SET", activebackground=theme['button_bg_active'], relief=theme['relief'],
                     bg=theme['button_bg_positive'], width=11, command=lambda: set_new_pass(),
                     font=theme['button_font'])
button_code.pack(side=RIGHT, pady=3, anchor=CENTER)
# endregion
# region email
label_email = Label(auth_frame, font=theme['font_main'], text="Email:", fg=theme['text_color'], bg=theme['bg'],
                    width=19, anchor=W)
entry_email = Entry(auth_frame, font=12, width=20, fg=theme['text_color'], bg=theme['entry'], relief=theme['relief'],
                    cursor=theme['cursor'])
# endregion
# region main menu
main_frame = LabelFrame(root, width=850, height=500, bg=theme['bg'], relief=theme['relief'])
group_frame = LabelFrame(root, width=850, height=500, bg=theme['bg'], relief=theme['relief'])
settings_frame = LabelFrame(root, width=600, height=500, bg=theme['bg'], relief=theme['frame_relief'])
menu_frame = ScrollableFrame(root)
start_new_chat = Label(menu_frame.scrollable_frame, font=theme['font_main'], bg="#606060", width=25, height=1,
                       fg=theme['text_color'], text=f"+ Add new chat", anchor=CENTER)
start_new_chat.pack(side=TOP, anchor=N, pady=2)
start_new_chat.bind("<Button-1>", lambda e: (menu_navigation("chat"), start_chat()))
button_chat = Button(top_frame, text="💬", activebackground=theme['button_bg_active'],
                     relief=theme['relief'], font=theme['button_font'],
                     bg=theme['button_bg_positive'], width=2, command=lambda: menu_navigation("chat"))
button_info = Button(top_frame, text="🔍", activebackground=theme['button_bg_active'],
                     bg=theme['button_bg'], font=theme['button_font'],
                     width=2, relief=theme['relief'], command=lambda: menu_navigation("info"))
button_settings = Button(top_frame, text="⚙", activebackground=theme['button_bg_active'],
                         width=2, bg=theme['button_bg'], relief=theme['relief'],
                         command=lambda: menu_navigation("set"), font=theme['button_font'])
button_logout = Button(top_frame, text="→", activebackground=theme['button_bg_active'],
                       bg=theme['button_bg_negative'], width=2, relief=theme['relief'], font=theme['button_font'],
                       command=lambda: logout())
button_back = Button(top_frame, text="BACK", activebackground=theme['button_bg_active'],
                     bg=theme['button_bg_negative'], width=17, relief=theme['relief'], font=theme['button_font'],
                     command=lambda: menu_navigation("chat"))
main2_frame = LabelFrame(main_frame, width=600, height=350, relief=FLAT, bg=theme['bg'])
main2_frame.pack(side=TOP, anchor=CENTER)
main2_frame2 = LabelFrame(group_frame, width=600, height=350, relief=FLAT, bg=theme['bg'])
main2_frame2.pack(side=TOP, anchor=CENTER)
# endregion
# region chat
chat_frame = LabelFrame(main2_frame, width=600, height=25, relief=FLAT, bg=theme['bg'])
chat_frame.pack(side=TOP, pady=2, anchor=W)
label_chat_id = Label(chat_frame, font=theme['font_main'], text="Current chat with: ", fg=theme['text_color'],
                      bg=theme['bg'], width=25, anchor=W)
label_chat_id.pack(side=LEFT, anchor=W)
frame = Frame(main2_frame, width=850, height=450)
frame.pack()
canvas = Text(frame, fg=theme['text_color'], bg=theme['entry'], width=105, cursor='arrow',
              selectforeground=theme['text_color'], selectbackground=theme['entry'])
scroll = Scrollbar(frame, command=canvas.yview, orient="vertical")
scroll.pack(side=RIGHT, fill=Y)
canvas.pack(side=RIGHT, expand=True, fill=BOTH)
canvas.config(yscrollcommand=scroll.set)
canvas.tag_config("url_tag", foreground="blue", underline=True)
canvas.tag_bind("url_tag", "<Button-1>", open_link)
button_refresh = Button(main_frame, text="REFRESH", activebackground=theme['button_bg_active'], width=120,
                        bg=theme['button_bg_positive'], relief=theme['relief'], command=lambda: get_all_messages())
button_refresh.pack(side=TOP, padx=3, pady=3, anchor=CENTER)
entry_msg = Entry(main_frame, font=10, width=85, relief=theme['relief'], fg=theme['text_color'], bg=theme['entry'],
                  cursor=theme['cursor'])
entry_msg.bind("<Return>", send_message_handler)
entry_msg.pack(side=LEFT, padx=3)
button_img = Button(main_frame, text="➕", activebackground=theme['button_bg_active'], bg=theme['button_bg_positive'],
                    width=3, relief=theme['relief'], command=lambda: send_document(), state='disabled')
button_img.pack(side=LEFT, anchor=E)
button_send = Button(main_frame, text="SEND", activebackground=theme['button_bg_active'], relief=theme['relief'],
                     bg=theme['button_bg_positive'], width=8, command=lambda: send(), state='disabled')
button_send.pack(side=LEFT, anchor=E, padx=3)
# endregion
# region settings
settings_frame_2 = LabelFrame(settings_frame, width=600, height=25, relief=FLAT, bg=theme['bg'])
settings_frame_2.pack(side=TOP, pady=2, anchor=N)
label_check = Label(settings_frame_2, font=10, text="  Update frequency:", fg=theme['text_color'], bg=theme['bg'],
                    width=18, anchor=W)
label_check.pack(side=LEFT, anchor=W)
label_check2 = Label(settings_frame_2, font=12, text="1 min", width=20, fg=theme['text_color'], bg=theme['bg'])
label_check2.pack(side=LEFT, padx=170, anchor=CENTER)
button_check_msg = Button(settings_frame_2, text="UPDATE", activebackground=theme['button_bg_active'], width=15,
                          bg=theme['button_bg_positive'], relief=theme['relief'], command=lambda: auto_check())
button_check_msg.pack(side=RIGHT, anchor=E)
settings_frame7 = LabelFrame(settings_frame, width=600, height=25, relief=FLAT, bg=theme['bg'])
settings_frame7.pack(side=TOP, pady=2, anchor=N)
label_chat = Label(settings_frame7, font=10, text="  Create chat:", fg=theme['text_color'], bg=theme['bg'], width=18,
                   anchor=W)
label_chat.pack(side=LEFT, anchor=W)
empty = Label(settings_frame7, text="", fg=theme['text_color'], bg=theme['bg'],
              width=3, anchor=W)
empty.pack(side=LEFT)
entry_chat = Entry(settings_frame7, font=12, width=20, fg=theme['text_color'], bg=theme['entry'],
                   cursor=theme['cursor'], relief=theme['relief'])
entry_chat.pack(side=LEFT, padx=150, anchor=CENTER)
empty = Label(settings_frame7, text="", fg=theme['text_color'], bg=theme['bg'],
              width=1, anchor=W)
empty.pack(side=LEFT)
button_c_chat = Button(settings_frame7, text="CREATE", activebackground=theme['button_bg_active'], width=15,
                       bg=theme['button_bg_positive'], relief=theme['relief'], command=lambda: create_chat())
button_c_chat.pack(side=RIGHT, anchor=E)
settings_frame8 = LabelFrame(settings_frame, width=600, height=25, relief=FLAT, bg=theme['bg'])
settings_frame8.pack(side=TOP, pady=2, anchor=N)
settings_frame9 = LabelFrame(settings_frame8, width=600, height=25, relief=FLAT, bg=theme['bg'])
settings_frame9.pack(side=LEFT, pady=2, anchor=N)
label_inv_id = Label(settings_frame9, font=10, text="  ID to invite:", fg=theme['text_color'], bg=theme['bg'],
                     width=18, anchor=W)
label_inv_id.pack(side=TOP, anchor=W)
entry_inv_id = Entry(settings_frame9, font=12, width=20, fg=theme['text_color'], bg=theme['entry'],
                     cursor=theme['cursor'], relief=theme['relief'])
entry_inv_id.pack(side=TOP, anchor=CENTER)
settings_frame10 = LabelFrame(settings_frame8, width=600, height=25, relief=FLAT, bg=theme['bg'])
settings_frame10.pack(side=LEFT, pady=2, padx=158, anchor=N)
label_gr_to_inv = Label(settings_frame10, font=10, text="Group id:", fg=theme['text_color'], bg=theme['bg'], width=18,
                        anchor=W)
label_gr_to_inv.pack(side=TOP, anchor=W)
entry_gr_to_inv = Entry(settings_frame10, font=12, width=20, fg=theme['text_color'], bg=theme['entry'],
                        cursor=theme['cursor'], relief=theme['relief'])
entry_gr_to_inv.pack(side=TOP, anchor=CENTER)
button_invite = Button(settings_frame8, text="INVITE", activebackground=theme['button_bg_active'], width=15,
                       bg=theme['button_bg_positive'], relief=theme['relief'], command=lambda: invite_to_group())
button_invite.pack(side=RIGHT, anchor=S)
settings_frame20 = LabelFrame(settings_frame, width=600, height=25, relief=FLAT, bg=theme['bg'])
settings_frame20.pack(side=TOP, pady=2, anchor=N)
settings_frame21 = LabelFrame(settings_frame20, width=600, height=25, relief=FLAT, bg=theme['bg'])
settings_frame21.pack(side=LEFT, pady=2, anchor=N)
label_kick_id = Label(settings_frame21, font=10, text="  ID to kick:", fg=theme['text_color'], bg=theme['bg'],
                      width=18, anchor=W)
label_kick_id.pack(side=TOP, anchor=W)
entry_kick_id = Entry(settings_frame21, font=12, width=20, fg=theme['text_color'], bg=theme['entry'],
                      cursor=theme['cursor'], relief=theme['relief'])
entry_kick_id.pack(side=TOP, anchor=CENTER)
settings_frame10 = LabelFrame(settings_frame20, width=600, height=25, relief=FLAT, bg=theme['bg'])
settings_frame10.pack(side=LEFT, pady=2, padx=158, anchor=N)
label_gr_to_kick = Label(settings_frame10, font=10, text="Group id:", fg=theme['text_color'], bg=theme['bg'],
                         width=18, anchor=W)
label_gr_to_kick.pack(side=TOP, anchor=W)
entry_gr_to_kick = Entry(settings_frame10, font=12, width=20, fg=theme['text_color'], bg=theme['entry'],
                         cursor=theme['cursor'], relief=theme['relief'])
entry_gr_to_kick.pack(side=TOP, anchor=CENTER)
button_kick = Button(settings_frame20, text="KICK", activebackground=theme['button_bg_active'], width=15,
                     bg=theme['button_bg_positive'], relief=theme['relief'], command=lambda: kick_from_group())
button_kick.pack(side=RIGHT, anchor=S)
settings_frame3 = LabelFrame(settings_frame, width=600, height=25, relief=FLAT, bg=theme['bg'])
settings_frame3.pack(side=TOP, pady=2, anchor=N)
settings_frame5 = LabelFrame(settings_frame3, width=600, height=25, relief=FLAT, bg=theme['bg'])
settings_frame5.pack(side=LEFT, pady=2, anchor=N)
label_old_pass = Label(settings_frame5, font=10, text="  Current password:", fg=theme['text_color'],
                       bg=theme['bg'], width=18, anchor=W)
label_old_pass.pack(side=TOP, anchor=W)
entry_old_pass = Entry(settings_frame5, font=12, width=20, fg=theme['text_color'], bg=theme['entry'],
                       cursor=theme['cursor'], relief=theme['relief'], show='•')
entry_old_pass.bind("<Return>", change_pass_handler)
entry_old_pass.pack(side=TOP, anchor=CENTER)
settings_frame6 = LabelFrame(settings_frame3, width=600, height=25, relief=FLAT, bg=theme['bg'])
settings_frame6.pack(side=LEFT, pady=2, padx=158, anchor=N)
label_new_pass = Label(settings_frame6, font=10, text="New password:", fg=theme['text_color'], bg=theme['bg'],
                       width=18, anchor=W)
label_new_pass.pack(side=TOP, anchor=W)
entry_new_pass = Entry(settings_frame6, font=12, width=20, fg=theme['text_color'], bg=theme['entry'],
                       cursor=theme['cursor'], relief=theme['relief'], show='•')
entry_new_pass.bind("<Return>", change_pass_handler)
entry_new_pass.pack(side=TOP, anchor=CENTER)
button_pass_font = Button(settings_frame3, text="CHANGE", activebackground=theme['button_bg_active'], width=15,
                          bg=theme['button_bg_positive'], relief=theme['relief'], command=lambda: change_password())
button_pass_font.pack(side=RIGHT, anchor=S)
settings_frame16 = LabelFrame(settings_frame, width=600, height=25, relief=FLAT, bg=theme['bg'])
settings_frame16.pack(side=TOP, pady=2, anchor=W)
entry_path = Entry(settings_frame16, font=12, width=72, fg=theme['text_color'], bg=theme['entry'],
                   cursor=theme['cursor'], relief=theme['relief'])
entry_path.pack(side=LEFT, padx=3)
entry_path.insert(0, get_browser_path())
empty = Label(settings_frame16, font=10, text="", fg=theme['text_color'], bg=theme['bg'],
              width=2, anchor=W)
empty.pack(side=LEFT, padx=5)
button_path = Button(settings_frame16, text="SAVE", activebackground=theme['button_bg_active'], width=15,
                     bg=theme['button_bg_positive'], relief=theme['relief'], command=lambda: save_browser_path())
button_path.pack(side=RIGHT, anchor=S)
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
settings_frame12.pack(side=TOP, anchor=CENTER)
d_z = Label(settings_frame12, font=15, text="DANGER ZONE", fg="red", bg=theme['bg'])
d_z.pack(side=TOP, padx=5)
button_delete = Button(settings_frame12, text="DELETE ACCOUNT DATA", bg=theme['button_bg_positive'],
                       activebackground=theme['button_bg_active'], width=113, relief=theme['relief'],
                       command=lambda: delete_account())
button_export = Button(settings_frame12, text="EXPORT DATA", bg=theme['button_bg_positive'],
                       activebackground=theme['button_bg_active'], width=113, relief=theme['relief'],
                       command=lambda: export_program_data())
button_import = Button(settings_frame12, text="IMPORT DATA", bg=theme['button_bg_positive'],
                       activebackground=theme['button_bg_active'], width=113, relief=theme['relief'],
                       command=lambda: import_program_data())
button_delete.pack(side=TOP, pady=5, anchor=CENTER)
button_export.pack(side=TOP, anchor=CENTER)
button_import.pack(side=TOP, pady=5, anchor=CENTER)
button_regenerate = Button(settings_frame12, text="REGENERATE ENCRYPTION KEYS", bg=theme['button_bg_positive'],
                           activebackground=theme['button_bg_active'], width=113, relief=theme['relief'],
                           command=lambda: regenerate_encryption_keys())
button_regenerate.pack(side=TOP, anchor=CENTER)
# endregion
# region json editor
choices = {'flat', 'raised', 'sunken', 'groove', 'ridge'}
choices2 = {'arrow', 'circle', 'clock', 'cross', 'dotbox', 'exchange', 'fleur', 'heart', 'man', 'mouse', 'pirate',
            'plus', 'shuttle', 'sizing', 'spider', 'spraycan', 'star', 'target', 'tcross', 'trek', 'watch'}
theme_editor_window = Toplevel(root)
theme_editor_window.withdraw()
theme_editor_window.title("Theme editor")
theme_editor_window.geometry("500x550+{}+{}".format(w, h))
theme_editor_window.resizable(False, False)
# theme_editor_window.overrideredirect(1)
theme_editor_window['bg'] = theme['bg']
test_color = LabelFrame(theme_editor_window, width=500, relief=FLAT, bg=theme['bg'])
test_color.pack(side=TOP)
label_text_box = Label(test_color, width=2, anchor=W)
label_text_box.pack(side=LEFT)
label_text = Label(test_color, font=theme['font_main'], text="Text color", fg=theme['text_color'],
                   bg=theme['bg'], width=25, anchor=W)
label_text.pack(side=LEFT)
entry_text = Entry(test_color, font=12, width=25, fg=theme['text_color'], bg=theme['entry'],
                   relief=theme['relief'], cursor=theme['cursor'])
entry_text.pack(side=LEFT)
entry_color = LabelFrame(theme_editor_window, width=500, relief=FLAT, bg=theme['bg'])
entry_color.pack(side=TOP, pady=5)
label_entry_box = Label(entry_color, width=2, anchor=W)
label_entry_box.pack(side=LEFT)
label_entry = Label(entry_color, font=theme['font_main'], text="Entry color", fg=theme['text_color'],
                    bg=theme['bg'], width=25, anchor=W)
label_entry.pack(side=LEFT)
entry_entry = Entry(entry_color, font=12, width=25, fg=theme['text_color'], bg=theme['entry'],
                    relief=theme['relief'], cursor=theme['cursor'])
entry_entry.pack(side=LEFT)
widgets_relief = LabelFrame(theme_editor_window, width=500, relief=FLAT, bg=theme['bg'])
widgets_relief.pack(side=TOP)
label_wid_box = Label(widgets_relief, width=2, anchor=W)
label_wid_box.pack(side=LEFT)
label_relief = Label(widgets_relief, font=theme['font_main'], text="Widgets relief", fg=theme['text_color'],
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
label_frame_box = Label(frame_relief, width=2, anchor=W)
label_frame_box.pack(side=LEFT)
label_frame_r = Label(frame_relief, font=theme['font_main'], text="Frame relief", fg=theme['text_color'],
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
label_bg_box = Label(bg_frame, width=2, anchor=W)
label_bg_box.pack(side=LEFT)
label_bg = Label(bg_frame, font=theme['font_main'], text="Background color", fg=theme['text_color'],
                 bg=theme['bg'], width=25, anchor=W)
label_bg.pack(side=LEFT)
entry_bg = Entry(bg_frame, font=12, width=25, fg=theme['text_color'], bg=theme['entry'],
                 relief=theme['relief'], cursor=theme['cursor'])
entry_bg.pack(side=LEFT)
sel_bg_frame = LabelFrame(theme_editor_window, width=500, relief=FLAT, bg=theme['bg'])
sel_bg_frame.pack(side=TOP)
label_sel_box = Label(sel_bg_frame, width=2, anchor=W)
label_sel_box.pack(side=LEFT)
label_sel_bg = Label(sel_bg_frame, font=theme['font_main'], text="Select background", fg=theme['text_color'],
                     bg=theme['bg'], width=25, anchor=W)
label_sel_bg.pack(side=LEFT)
entry_sel_bg = Entry(sel_bg_frame, font=12, width=25, fg=theme['text_color'], bg=theme['entry'],
                     relief=theme['relief'], cursor=theme['cursor'])
entry_sel_bg.pack(side=LEFT)
font_frame = LabelFrame(theme_editor_window, width=500, relief=FLAT, bg=theme['bg'])
font_frame.pack(side=TOP, pady=5)
label_font_box = Label(font_frame, width=2, anchor=W)
label_font_box.pack(side=LEFT)
label_font = Label(font_frame, font=theme['font_main'], text="Main font", fg=theme['text_color'],
                   bg=theme['bg'], width=25, anchor=W)
label_font.pack(side=LEFT)
entry_font = Entry(font_frame, font=12, width=25, fg=theme['text_color'], bg=theme['entry'],
                   relief=theme['relief'], cursor=theme['cursor'])
entry_font.pack(side=LEFT)
font_users_frame = LabelFrame(theme_editor_window, width=500, relief=FLAT, bg=theme['bg'])
font_users_frame.pack(side=TOP)
label_users_box = Label(font_users_frame, width=2, anchor=W)
label_users_box.pack(side=LEFT)
label_font_u = Label(font_users_frame, font=theme['font_main'], text="Users frame font", fg=theme['text_color'],
                     bg=theme['bg'], width=25, anchor=W)
label_font_u.pack(side=LEFT)
entry_font_u = Entry(font_users_frame, font=12, width=25, fg=theme['text_color'], bg=theme['entry'],
                     relief=theme['relief'], cursor=theme['cursor'])
entry_font_u.pack(side=LEFT)
font_b_frame = LabelFrame(theme_editor_window, width=500, relief=FLAT, bg=theme['bg'])
font_b_frame.pack(side=TOP, pady=5)
label_font_b_box = Label(font_b_frame, width=2, anchor=W)
label_font_b_box.pack(side=LEFT)
label_font_b = Label(font_b_frame, font=theme['font_main'], text="Buttons font", fg=theme['text_color'],
                     bg=theme['bg'], width=25, anchor=W)
label_font_b.pack(side=LEFT)
entry_font_b = Entry(font_b_frame, font=12, width=25, fg=theme['text_color'], bg=theme['entry'],
                     relief=theme['relief'], cursor=theme['cursor'])
entry_font_b.pack(side=LEFT)
frame_bg_b = LabelFrame(theme_editor_window, width=500, relief=FLAT, bg=theme['bg'])
frame_bg_b.pack(side=TOP)
label_bg_b_box = Label(frame_bg_b, width=2, anchor=W)
label_bg_b_box.pack(side=LEFT)
label_bg_b = Label(frame_bg_b, font=theme['font_main'], text="Buttons background", fg=theme['text_color'],
                   bg=theme['bg'], width=25, anchor=W)
label_bg_b.pack(side=LEFT)
entry_bg_b = Entry(frame_bg_b, font=12, width=25, fg=theme['text_color'], bg=theme['entry'],
                   relief=theme['relief'], cursor=theme['cursor'])
entry_bg_b.pack(side=LEFT)
frame_bg_b_pos = LabelFrame(theme_editor_window, width=500, relief=FLAT, bg=theme['bg'])
frame_bg_b_pos.pack(side=TOP, pady=5)
label_pos_box = Label(frame_bg_b_pos, width=2, anchor=W)
label_pos_box.pack(side=LEFT)
label_bg_b_pos = Label(frame_bg_b_pos, font=theme['font_main'], text="Buttons background positive",
                       fg=theme['text_color'], bg=theme['bg'], width=25, anchor=W)
label_bg_b_pos.pack(side=LEFT)
entry_bg_b_pos = Entry(frame_bg_b_pos, font=12, width=25, fg=theme['text_color'], bg=theme['entry'],
                       relief=theme['relief'], cursor=theme['cursor'])
entry_bg_b_pos.pack(side=LEFT)
frame_bg_b_neg = LabelFrame(theme_editor_window, width=500, relief=FLAT, bg=theme['bg'])
frame_bg_b_neg.pack(side=TOP)
label_neg_box = Label(frame_bg_b_neg, width=2, anchor=W)
label_neg_box.pack(side=LEFT)
label_bg_b_neg = Label(frame_bg_b_neg, font=theme['font_main'], text="Buttons background negative",
                       fg=theme['text_color'], bg=theme['bg'], width=25, anchor=W)
label_bg_b_neg.pack(side=LEFT)
entry_bg_b_neg = Entry(frame_bg_b_neg, font=12, width=25, fg=theme['text_color'], bg=theme['entry'],
                       relief=theme['relief'], cursor=theme['cursor'])
entry_bg_b_neg.pack(side=LEFT)
frame_b_act = LabelFrame(theme_editor_window, width=500, relief=FLAT, bg=theme['bg'])
frame_b_act.pack(side=TOP, pady=5)
label_act_box = Label(frame_b_act, width=2, anchor=W)
label_act_box.pack(side=LEFT)
label_b_act = Label(frame_b_act, font=theme['font_main'], text="Buttons active background",
                    fg=theme['text_color'], bg=theme['bg'], width=25, anchor=W)
label_b_act.pack(side=LEFT)
entry_b_act = Entry(frame_b_act, font=12, width=25, fg=theme['text_color'], bg=theme['entry'],
                    relief=theme['relief'], cursor=theme['cursor'])
entry_b_act.pack(side=LEFT)
frame_cursor = LabelFrame(theme_editor_window, width=500, relief=FLAT, bg=theme['bg'])
frame_cursor.pack(side=TOP)
label_cur_box = Label(frame_cursor, width=2, anchor=W)
label_cur_box.pack(side=LEFT)
label_cursor = Label(frame_cursor, font=theme['font_main'], text="Input fields cursor",
                     fg=theme['text_color'], bg=theme['bg'], width=25, anchor=W)
label_cursor.pack(side=LEFT)
popup_cur = OptionMenu(frame_cursor, cursors, *choices2)
popup_cur.pack(side=TOP)
popup_cur.configure(width=31, relief=theme['relief'], fg=theme['text_color'], bg=theme['entry'],
                    activebackground=theme['entry'], highlightthickness=0, height=1)
popup_cur["menu"].configure(bg=theme['entry'], fg=theme['text_color'], relief=theme['relief'],
                            activebackground=theme['button_bg_active'], borderwidth=0)
# print(popup_cur.keys())
button_save = Button(theme_editor_window, text="SAVE", bg=theme['button_bg_positive'], relief=theme['relief'],
                     activebackground=theme['button_bg_active'], width=67, command=lambda: theme_editor_save())
button_save.pack(side=TOP, pady=5)
# endregion
# region info
main1_frame = LabelFrame(root, width=850, height=500, relief=theme['relief'], bg=theme['bg'])
info_frame = LabelFrame(main1_frame, bg=theme['bg'], relief=theme['relief'])
info_frame.pack(side=LEFT, anchor=NW)
info_frame_2 = LabelFrame(info_frame, bg=theme['bg'], relief=theme['relief'])
info_frame_2.pack(side=TOP, anchor=NW)
entry_user_search = Entry(info_frame_2, font=10, width=87, relief=theme['relief'], fg=theme['text_color'],
                          bg=theme['entry'], cursor=theme['cursor'])
entry_user_search.pack(side=LEFT, padx=3)
button_search = Button(info_frame_2, text="SEARCH", activebackground=theme['button_bg_active'], width=8,
                       bg=theme['button_bg_positive'], relief=theme['relief'], command=lambda: search_user())
button_search.pack(side=LEFT, anchor=E, padx=3)
frame_users = Frame(info_frame, width=800, height=400)
frame_users.pack()
canvas_users = Treeview(frame_users, height=29, cursor="arrow", columns=(0, 1, 2), show="headings", style="t_style")
scroll_users = Scrollbar(frame_users, command=canvas_users.yview)
scroll_users.pack(side=RIGHT, fill=Y)
canvas_users.pack(side=RIGHT, expand=True, fill=BOTH)
canvas_users.config(yscrollcommand=scroll_users.set)
canvas_users.heading(0, text="ID", anchor=W)
canvas_users.heading(1, text="Username", anchor=W)
canvas_users.heading(2, text="Last activity", anchor=W)
canvas_users.column(0, width=60, stretch=NO)
canvas_users.column(1, width=567)
canvas_users.column(2, width=200, stretch=NO)
canvas_users.tag_configure("users_tag", background=theme['entry'], foreground=theme['text_color'])
label_loading = Label(root, font=10, text="LOADING", fg=theme['text_color'], bg=theme['bg'])
# endregion
get_update_time()
if time_to_check is not None:
    if int(time_to_check) != -1:
        root.after(int(time_to_check) * 1000, loop_msg_func)
# print(root.winfo_children())
root.after(570000, refresh_token)
if __name__ == "__main__":
    root.title("Chat")
    root.overrideredirect(1)
    root.geometry("200x200+{}+{}".format(w, h))
    root.resizable(False, False)
    root['bg'] = theme['bg']
    auto_login()
    api_awake()
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()
