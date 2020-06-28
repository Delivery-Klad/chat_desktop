import psycopg2
import bcrypt
import rsa
import tkinter as tk
from tkinter import *
from tkinter import messagebox

root = tk.Tk()
w = root.winfo_screenwidth() // 2 - 140
h = root.winfo_screenheight() // 2 - 100
user_login = ''
user_id = ''
private_key = rsa.PrivateKey(1, 2, 3, 4, 5)


def exception_handler(e, connect, cursor):
    try:
        cursor.close()
        connect.close()
        print(e)
    except Exception as e:
        print(e)


def pg_connect():
    try:
        con = psycopg2.connect(
            host="ec2-54-75-244-161.eu-west-1.compute.amazonaws.com",
            database="d8fi2kbfpchos",
            user="iutnqyyujjskrr",
            port="5432",
            password="45be3b8ccf0ce93d0e142ec546edaa8a067370f5c050b92b4c181730fb2c9814")
        cur = con.cursor()
        return con, cur
    except Exception as e:
        print(e)


def create_tables():
    connect, cursor = pg_connect()
    try:
        # cursor.execute("DROP TABLE users")
        # cursor.execute("DROP TABLE messages")
        cursor.execute('CREATE TABLE IF NOT EXISTS users(id INTEGER,'
                       'login TEXT,'
                       'password TEXT,'
                       'pubkey TEXT)')
        cursor.execute('CREATE TABLE IF NOT EXISTS messages(from_id INTEGER,'
                       'to_id INTEGER,'
                       'message BYTEA)')
        connect.commit()
        cursor.close()
        connect.close()
    except Exception as e:
        exception_handler(e, connect, cursor)


def check_input(password: str, log: str):
    if len(log) < 5:
        messagebox.showerror('Input error', 'Login length must be more than 5 characters')
        return False
    if len(password) < 8:
        messagebox.showerror('Input error', 'Password length must be more than 8 characters')
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


def login(*args):
    global user_login
    global user_id
    connect, cursor = pg_connect()
    try:
        if len(entry_log.get()) == 0 or len(entry_pass.get()) == 0:
            messagebox.showerror('Input error', 'Fill all input fields')
            return
        try:
            cursor.execute("SELECT password FROM users WHERE login='{0}'".format(entry_log.get()))
            res = cursor.fetchall()[0][0]
            hashed_password = res.encode('utf-8')
            password = entry_pass.get().encode('utf-8')
            if not bcrypt.checkpw(password, hashed_password):
                cursor.close()
                connect.close()
                messagebox.showerror('Input error', 'Wrong password')
                return
        except IndexError:
            cursor.close()
            connect.close()
            messagebox.showerror('Input error', 'User not found')
            return
        user_login = entry_log.get()
        user_id = get_id(cursor)
        get_message()
        get_private_key()
        hide_auth_menu()
        cursor.close()
        connect.close()
    except Exception as e:
        exception_handler(e, connect, cursor)


def register():
    connect, cursor = pg_connect()
    try:
        if len(entry_log.get()) == 0 or len(entry_pass.get()) == 0:
            messagebox.showerror('Input error', 'Fill all input fields')
            cursor.close()
            connect.close()
            return
        if not check_input(entry_pass.get(), entry_log.get()):
            cursor.close()
            connect.close()
            return
        try:
            cursor.execute("SELECT COUNT(*) FROM users WHERE login = '{0}'".format(str(entry_log.get())))
            res = cursor.fetchall()[0][0]
            if res != 0:
                cursor.close()
                connect.close()
                messagebox.showerror('Input error', 'User already register')
                return
        except Exception as e:
            print(e)
        hashed_pass = bcrypt.hashpw(entry_pass.get().encode('utf-8'), bcrypt.gensalt())
        hashed_pass = str(hashed_pass)[2:-1]
        cursor.execute("SELECT MAX(id) FROM users")
        max_id = cursor.fetchall()[0][0]
        if max_id is not None:
            max_id += 1
        else:
            max_id = 0
        cursor.execute("INSERT INTO users VALUES ({0}, '{1}', '{2}', '{3}')".format(max_id, entry_log.get(),
                                                                                    hashed_pass, keys_generation()))
        connect.commit()
        cursor.close()
        connect.close()
    except Exception as e:
        exception_handler(e, connect, cursor)


def get_id(cursor):
    global user_login
    try:
        cursor.execute("SELECT id FROM users WHERE login='{0}'".format(user_login))
        res = cursor.fetchall()
        return res[0][0]
    except Exception as e:
        print(e)


def hide_auth_menu():
    global w
    global h
    w -= 200
    auth_frame.pack_forget()
    root.geometry("750x270+{}+{}".format(w, h))
    entry_id.focus_set()
    menu_frame.pack(side=LEFT, pady=5, anchor=N)
    main_frame.pack(side=LEFT, anchor=CENTER)


def menu_navigation(menu: str):
    if menu == "chat":
        button_chat.configure(bg="#2E8B57")
        button_info.configure(bg="#A9A9A9")
        button_settings.configure(bg="#A9A9A9")
        main1_frame.pack_forget()
        settings_frame.pack_forget()
        main_frame.pack(side=LEFT, anchor=CENTER)
    elif menu == "set":
        button_chat.configure(bg="#A9A9A9")
        button_info.configure(bg="#A9A9A9")
        button_settings.configure(bg="#2E8B57")
        main_frame.pack_forget()
        main1_frame.pack_forget()
        settings_frame.pack(side=LEFT, anchor=N)
    elif menu == "info":
        button_chat.configure(bg="#A9A9A9")
        button_info.configure(bg="#2E8B57")
        button_settings.configure(bg="#A9A9A9")
        main_frame.pack_forget()
        settings_frame.pack_forget()
        main1_frame.pack(side=LEFT, anchor=NW)


def get_user_info():
    connect, cursor = pg_connect()
    try:
        if entry_id_or_nick.get().isdigit():
            res = get_user_nickname(int(entry_id_or_nick.get()), cursor)
        else:
            res = get_user_id(entry_id_or_nick.get(), cursor)
        cursor.close()
        connect.close()
        if res is None:
            messagebox.showerror('Input error', 'User not found')
            return
        entry_res.configure(state='normal')
        entry_res.delete(0, tk.END)
        entry_res.insert(0, res)
        entry_res.configure(state='disabled')
    except Exception as e:
        exception_handler(e, connect, cursor)


def get_user_nickname(user, cursor):
    try:
        cursor.execute("SELECT login FROM users WHERE id={0}".format(user))
        res = cursor.fetchall()
        return res[0][0]
    except IndexError:
        return None
    except Exception as e:
        print(e)


def get_user_id(user, cursor):
    try:
        cursor.execute("SELECT id FROM users WHERE login='{0}'".format(user))
        res = cursor.fetchall()
        return res[0][0]
    except IndexError:
        return None
    except Exception as e:
        print(e)


def send_message():
    global user_id
    connect, cursor = pg_connect()
    try:
        if len(entry_id.get()) == 0 or len(entry_msg.get()) == 0:
            messagebox.showerror('Input error', 'Fill all input fields')
            cursor.close()
            connect.close()
            return
        for i in entry_msg.get():
            if ord(i) < 32 or ord(i) > 1366:
                messagebox.showerror('Input error', 'Unsupported symbols')
                cursor.close()
                connect.close()
                return
        to_id = int(entry_id.get())
        msg = entry_msg.get()
        cursor.execute("SELECT pubkey FROM users WHERE id={0}".format(to_id))
        res = cursor.fetchall()[0][0]
        encrypt_msg = encrypt(msg, res)
        cursor.execute("INSERT INTO messages VALUES ({0}, {1}, {2})".format(user_id, to_id, encrypt_msg))
        entry_msg.delete(0, tk.END)
        connect.commit()
        cursor.close()
        connect.close()
    except Exception as e:
        exception_handler(e, connect, cursor)


def get_message():
    global user_id
    connect, cursor = pg_connect()
    try:
        cursor.execute("SELECT * FROM messages WHERE to_id={0}".format(user_id))
        res = cursor.fetchall()
        cursor.execute("DELETE FROM messages WHERE to_id={0}".format(user_id))
        connect.commit()
        for i in res:
            decrypt_msg = decrypt(i[2])
            nickname = get_user_nickname(i[0], cursor)
            content = '{0}: {1}'.format(nickname, decrypt_msg)
            list_box2.insert(tk.END, content)
        cursor.close()
        connect.close()
    except Exception as e:
        exception_handler(e, connect, cursor)


def encrypt(msg: str, pubkey):
    try:
        pubkey = pubkey.split(', ')
        pubkey = rsa.PublicKey(int(pubkey[0]), int(pubkey[1]))
        encrypt_message = rsa.encrypt(msg.encode('utf-8'), pubkey)
        encrypt_message = encrypt_message
        return psycopg2.Binary(encrypt_message)
    except Exception as e:
        print(e)


def decrypt(msg: bytes):
    global private_key
    try:
        decrypted_message = rsa.decrypt(msg, private_key)
        return decrypted_message.decode('utf-8')
    except Exception as e:
        print(e)


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
        if len(entry_id.get()) != 0 and len(entry_msg.get()) != 0:
            send_message()
        elif len(entry_id.get()) == 0:
            pass
        elif len(entry_msg.get()) == 0:
            entry_msg.focus_set()
    elif str(root.focus_get()) == ".!labelframe2.!entry2":
        if len(entry_id.get()) != 0 and len(entry_msg.get()) != 0:
            send_message()
        elif len(entry_msg.get()) == 0:
            pass
        elif len(entry_id.get()) == 0:
            entry_id.focus_set()


def regenerate_keys():
    global user_id
    connect, cursor = pg_connect()
    try:
        cursor.execute("UPDATE users SET pubkey='{0}' WHERE id={1}".format(keys_generation(), user_id))
        connect.commit()
        cursor.close()
        connect.close()
    except Exception as e:
        exception_handler(e, connect, cursor)


def keys_generation():
    global private_key
    (pubkey, privkey) = rsa.newkeys(512)
    pubkey = str(pubkey)[10:-1]
    with open("priv_key.PEM", 'w') as file:
        file.write(privkey.save_pkcs1().decode('ascii'))
    private_key = privkey
    return pubkey


def get_private_key():
    try:
        global private_key
        with open("priv_key.PEM", 'rb') as file:
            data = file.read()
        private_key = rsa.PrivateKey.load_pkcs1(data)
    except FileNotFoundError:
        pass


def change_text_font():
    if len(entry_font.get()) == 0:
        messagebox.showerror("Input error", "Input field must be filled")
        return
    if not entry_font.get().isdigit():
        messagebox.showerror("Input error", "Font must be a number")
        return
    for i in labels:
        i.configure(font=int(entry_font.get()))
    messagebox.showinfo("OOPS", "Not worked yet")


def change_but_font():
    if len(entry_b_font.get()) == 0:
        messagebox.showerror("Input error", "Input field must be filled")
        return
    if not entry_b_font.get().isdigit():
        messagebox.showerror("Input error", "Font must be a number")
        return
    for i in buttons:
        i.configure(font=int(entry_b_font.get()))
    messagebox.showinfo("OOPS", "Not worked yet")


def change_password():
    try:
        messagebox.showinfo("OOPS", "Not worked yet")
    except Exception as e:
        print(e)


def loop(*args):
    while True:
        print(1)
        root.update()


create_tables()
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
entry_pass = tk.Entry(auth_frame, font=12, width=20, fg="black", show='*')
entry_pass.bind("<Return>", login)
entry_pass.pack(side=TOP)
button_login = tk.Button(auth_frame, text="LOGIN", bg='#2E8B57', width=11, command=lambda: login())
button_login.pack(side=LEFT, pady=3, anchor=CENTER)
button_reg = tk.Button(auth_frame, text="REGISTER", bg='#2E8B57', width=11, command=lambda: register())
button_reg.pack(side=RIGHT, pady=3, anchor=CENTER)
# endregion
# region main menu
main_frame = LabelFrame(root, width=600, height=270)
settings_frame = LabelFrame(root, width=600, height=270)
menu_frame = LabelFrame(root, width=150, height=270, relief=FLAT)
button_chat = tk.Button(menu_frame, text="CHAT", bg='#2E8B57', width=17, command=lambda: menu_navigation("chat"))
button_chat.pack(side=TOP, anchor=N)
button_info = tk.Button(menu_frame, text="INFO", bg='#A9A9A9', width=17, command=lambda: menu_navigation("info"))
button_info.pack(side=TOP, pady=5, anchor=N)
button_settings = tk.Button(menu_frame, text="SETTINGS", bg='#A9A9A9', width=17, command=lambda: menu_navigation("set"))
button_settings.pack(side=TOP, anchor=N)
main2_frame = LabelFrame(main_frame, width=600, height=350, relief=FLAT)
main2_frame.pack(side=TOP, anchor=CENTER)
# endregion
# region chat
list_box2 = Listbox(main2_frame, selectmode=EXTENDED, font=10, width=67, height=10, fg="black")
list_box2.pack(side=LEFT)
button_refresh = tk.Button(main_frame, text="REFRESH", bg='#2E8B57', width=85, command=lambda: get_message())
button_refresh.pack(side=TOP, pady=3, anchor=CENTER)
entry_id = tk.Entry(main_frame, font=10, width=8)
entry_id.bind("<Return>", send_message_handler)
entry_id.pack(side=LEFT, padx=6)
entry_msg = tk.Entry(main_frame, font=10, width=50)
entry_msg.bind("<Return>", send_message_handler)
entry_msg.pack(side=LEFT, padx=3)
button_send = tk.Button(main_frame, text="SEND", bg='#2E8B57', width=7, command=lambda: send_message())
button_send.pack(side=LEFT, anchor=E)
entry_log.focus_set()
# root.after(500, loop)
# endregion
# region settings
settings_frame1 = LabelFrame(settings_frame, width=600, height=25, relief=FLAT)
settings_frame1.pack(side=TOP, pady=2, anchor=N)
label_font = tk.Label(settings_frame1, font=10, text="  Text font:", fg="black", width=18, anchor=W)
label_font.pack(side=LEFT, anchor=W)
entry_font = tk.Entry(settings_frame1, font=12, width=20, fg="black")
entry_font.pack(side=LEFT, padx=80, anchor=CENTER)
button_font = tk.Button(settings_frame1, text="SET", bg='#2E8B57', width=15, command=lambda: change_text_font())
button_font.pack(side=RIGHT, anchor=E)
settings_frame2 = LabelFrame(settings_frame, width=600, height=25, relief=FLAT)
settings_frame2.pack(side=TOP, pady=2, anchor=N)
label_b_font = tk.Label(settings_frame2, font=10, text="  Buttons font:", fg="black", width=18, anchor=W)
label_b_font.pack(side=LEFT, anchor=W)
entry_b_font = tk.Entry(settings_frame2, font=12, width=20, fg="black")
entry_b_font.pack(side=LEFT, padx=80, anchor=CENTER)
button_b_font = tk.Button(settings_frame2, text="SET", bg='#2E8B57', width=15, command=lambda: change_but_font())
button_b_font.pack(side=RIGHT, anchor=E)
settings_frame3 = LabelFrame(settings_frame, width=600, height=25, relief=FLAT)
settings_frame3.pack(side=TOP, pady=2, anchor=N)

settings_frame5 = LabelFrame(settings_frame3, width=600, height=25, relief=FLAT)
settings_frame5.pack(side=LEFT, pady=2, padx=2, anchor=N)
label_old_pass = tk.Label(settings_frame5, font=10, text="Old password:", fg="black", width=18, anchor=W)
label_old_pass.pack(side=TOP, anchor=W)
entry_old_pass = tk.Entry(settings_frame5, font=12, width=20, fg="black")
entry_old_pass.pack(side=TOP, anchor=CENTER)

settings_frame6 = LabelFrame(settings_frame3, width=600, height=25, relief=FLAT)
settings_frame6.pack(side=LEFT, pady=2, padx=53, anchor=N)
label_new_pass = tk.Label(settings_frame6, font=10, text="New password:", fg="black", width=18, anchor=W)
label_new_pass.pack(side=TOP, anchor=W)
entry_new_pass = tk.Entry(settings_frame6, font=12, width=20, fg="black")
entry_new_pass.pack(side=TOP, anchor=CENTER)

button_pass_font = tk.Button(settings_frame3, text="CHANGE", bg='#2E8B57', width=17, command=lambda: change_but_font())
button_pass_font.pack(side=RIGHT, anchor=S)

settings_frame4 = LabelFrame(settings_frame, width=600, height=25, relief=FLAT)
settings_frame4.pack(side=TOP, pady=2, anchor=N)
button_b_font = tk.Button(settings_frame4, text="REGENERATE CRYPT KEYS", bg='#2E8B57', width=100,
                          command=lambda: regenerate_keys())
button_b_font.pack(side=TOP, anchor=CENTER)
# endregion
# region info
main1_frame = LabelFrame(root, width=600, height=350, relief=SUNKEN)
label_info = tk.Label(main1_frame, font=10, text="ID/Nickname", fg="black", width=18)
label_info.pack(side=TOP, anchor=CENTER)
entry_res = tk.Entry(main1_frame, font=10, width=20, state='disabled')
entry_res.pack(side=TOP, padx=2, pady=3, anchor=CENTER)
entry_id_or_nick = tk.Entry(main1_frame, font=10, width=20)
entry_id_or_nick.pack(side=TOP, padx=2, anchor=CENTER)
button_check = tk.Button(main1_frame, text="CHECK", bg='#2E8B57', width=25, command=lambda: get_user_info())
button_check.pack(side=TOP, anchor=CENTER)
# endregion

labels = [label_user, label_password, list_box2, entry_id, entry_msg, label_old_pass, entry_old_pass, entry_id_or_nick,
          label_info, entry_res, entry_new_pass, label_new_pass, entry_font, entry_b_font, label_font, label_b_font]
buttons = []

if __name__ == "__main__":
    root.title("Chat")
    root.geometry("200x130+{}+{}".format(w, h))
    root.resizable(False, False)
    root.mainloop()
