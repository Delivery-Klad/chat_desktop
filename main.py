import os
import psycopg2
import bcrypt
import rsa
import tkinter as tk
from tkinter import *
from tkinter import messagebox
from tkinter import filedialog
from PIL import Image as image1
from PIL import ImageTk as image2
import base64

root = tk.Tk()
spacing = 0
w = root.winfo_screenwidth() // 2 - 140
h = root.winfo_screenheight() // 2 - 100
user_login = ''
user_id = ''
var = IntVar()
private_key = rsa.PrivateKey(1, 2, 3, 4, 5)
files_dir = 'files'
auto_fill_data_file = files_dir + '/rem.rm'
private_key_file = files_dir + '/priv_key.PEM'
try:
    os.mkdir(files_dir)
except FileExistsError:
    pass


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


def auto_check_message():
    try:
        get_message()
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


def check_password(cursor, log, pas):
    try:
        cursor.execute("SELECT password FROM users WHERE login='{0}'".format(log))
        res = cursor.fetchall()[0][0]
        hashed_password = res.encode('utf-8')
        if bcrypt.checkpw(pas, hashed_password):
            return "True"
        return "False"
    except IndexError:
        return "None"
    except Exception as e:
        print(e)


def auto_login():
    global user_login
    global user_id
    psw, lgn = '', ''
    try:
        with open(auto_fill_data_file, 'r') as file:
            res = file.read().split('  ', 1)
        if len(res) == 1:
            return
        tmp = res[0].split(' ')
        for i in tmp:
            lgn += chr(int(i) - 1)
        tmp = res[1].split(' ')
        tmp.pop(len(tmp) - 1)
        for i in tmp:
            psw += chr(int(i) - 2)
        entry_log.insert(0, lgn)
        entry_pass.insert(0, psw)
        var.set(1)
    except FileNotFoundError:
        pass
    except Exception as e:
        print(e)


def clear_auto_login():
    with open(auto_fill_data_file, 'w') as file:
        file.write('')


def fill_auto_login_file(lgn, psw):
    with open(auto_fill_data_file, 'w') as file:
        file.write('')
    with open(auto_fill_data_file, 'a') as file:
        for i in lgn:
            file.write(str(ord(i) + 1) + ' ')
        file.write(' ')
        for i in psw:
            file.write(str(ord(i) + 2) + ' ')


def login(*args):
    global user_login
    global user_id
    connect, cursor = pg_connect()
    try:
        if len(entry_log.get()) == 0 or len(entry_pass.get()) == 0:
            messagebox.showerror('Input error', 'Fill all input fields')
            return
        res = check_password(cursor, entry_log.get(), entry_pass.get().encode('utf-8'))
        if res == "False":
            cursor.close()
            connect.close()
            messagebox.showerror('Input error', 'Wrong password')
            return
        elif res == "None":
            cursor.close()
            connect.close()
            messagebox.showerror('Input error', 'User not found')
            return
        if var.get() == 0:
            clear_auto_login()
        else:
            fill_auto_login_file(entry_log.get(), entry_pass.get())
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
    root.geometry("1000x500+{}+{}".format(w, h))
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
        if not entry_id.get().isdigit():
            messagebox.showerror('Input error', 'Id must be a number')
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
        encrypt_msg = encrypt(msg.encode('utf-8'), res)
        cursor.execute("INSERT INTO messages VALUES ({0}, {1}, {2})".format(user_id, to_id, encrypt_msg))
        entry_msg.delete(0, tk.END)
        connect.commit()
        cursor.close()
        connect.close()
    except Exception as e:
        exception_handler(e, connect, cursor)


def send_image():
    global user_id
    connect, cursor = pg_connect()
    try:
        if len(entry_id.get()) == 0:
            messagebox.showerror('Input error', 'Fill "id" input field')
            return
        path = filedialog.askopenfilename(filetypes=(("image", "*.png"), ("image", "*.jpg")))
        if len(path) == 0:
            return
        original_img = image1.open(path)
        width, height = original_img.size
        while width > 840:
            width = round(width * 0.8)
            height = round(height * 0.8)
        while height > 400:
            width = round(width * 0.8)
            height = round(height * 0.8)
        original_img.thumbnail((width, height), image1.ANTIALIAS)
        original_img.save('resized_image.png')
        original_img.close()
        with open('resized_image.png', 'rb') as file:
            b64 = base64.b64encode(file.read())
        cursor.execute("INSERT INTO messages VALUES ({0}, {1}, {2})".format(user_id, entry_id.get(), psycopg2.Binary(b64)))
        os.remove('resized_image.png')
        connect.commit()
        cursor.close()
        connect.close()
    except Exception as e:
        exception_handler(e, connect, cursor)


def get_message():
    global user_id, spacing
    connect, cursor = pg_connect()
    try:
        cursor.execute("SELECT * FROM messages WHERE to_id={0}".format(user_id))
        res = cursor.fetchall()
        cursor.execute("DELETE FROM messages WHERE to_id={0}".format(user_id))
        connect.commit()
        for i in res:
            decrypt_msg = decrypt(i[2])
            nickname = get_user_nickname(i[0], cursor)
            if decrypt_msg is None:
                content = '{0}: attachment'.format(nickname)
                widget = Label(canvas, text=content, bg='white', fg='black', font=14)
                canvas.create_window(0, spacing, window=widget, anchor='nw')
                spacing += 25
                canvas.config(scrollregion=canvas.bbox("all"))
                with open('tmp_img.png', 'wb') as file:
                    file.write(base64.b64decode(i[2]))
                im = image1.open('tmp_img.png')
                photo = image2.PhotoImage(im)
                im.close()
                os.remove('tmp_img.png')
                widget = Label(canvas, image=photo, fg='black')
                widget.image = photo
                canvas.create_window(0, spacing, window=widget, anchor='nw')
                spacing += photo.height() + 2
            else:
                content = '{0}: {1}'.format(nickname, decrypt_msg)
                widget = Label(canvas, text=content, bg='white', fg='black', font=14)
                canvas.create_window(0, spacing, window=widget, anchor='nw')
                spacing += 25
        canvas.config(scrollregion=canvas.bbox("all"))
        cursor.close()
        connect.close()
    except Exception as e:
        exception_handler(e, connect, cursor)


def encrypt(msg: bytes, pubkey):
    try:
        pubkey = pubkey.split(', ')
        pubkey = rsa.PublicKey(int(pubkey[0]), int(pubkey[1]))
        encrypt_message = rsa.encrypt(msg, pubkey)
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
    try:
        (pubkey, privkey) = rsa.newkeys(1024)
        pubkey = str(pubkey)[10:-1]
        with open(private_key_file, 'w') as file:
            file.write(privkey.save_pkcs1().decode('ascii'))
        private_key = privkey
        return pubkey
    except Exception as e:
        print(e)


def get_private_key():
    try:
        global private_key
        with open(private_key_file, 'rb') as file:
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
    global user_login
    connect, cursor = pg_connect()
    try:
        res = check_password(cursor, user_login, entry_old_pass.get().encode('utf-8'))
        if res == "False":
            messagebox.showerror("Input error", "Current password is wrong")
            cursor.close()
            connect.close()
            return
        if check_input(entry_new_pass.get(), entry_old_pass.get()):
            hashed_pass = bcrypt.hashpw(entry_new_pass.get().encode('utf-8'), bcrypt.gensalt())
            hashed_pass = str(hashed_pass)[2:-1]
            cursor.execute("UPDATE users SET password='{0}' WHERE login='{1}'".format(hashed_pass, user_login))
            connect.commit()
            messagebox.showinfo("Success", "Password has been changed")
        cursor.close()
        connect.close()
        with open(auto_fill_data_file, 'r') as file:
            res = file.read().split('  ', 1)
        if len(res) == 1:
            return
        fill_auto_login_file(user_login, entry_new_pass.get())
    except Exception as e:
        exception_handler(e, connect, cursor)


def logout():
    global w
    global h
    w += 200
    menu_navigation("chat")
    menu_frame.pack_forget()
    main_frame.pack_forget()
    root.geometry("200x160+{}+{}".format(w, h))
    entry_log.focus_set()
    auth_frame.pack(side=TOP, anchor=CENTER)


def loop(*args):
    while True:
        print(1)
        root.update()


def OnMouseWheel(event):
    canvas.yview("scroll", event.delta, "units")
    return "break"


def auto_check():
    button_check.configure(text='11 Min')
    print(1)


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
entry_pass = tk.Entry(auth_frame, font=12, width=20, fg="black", show='•')
entry_pass.bind("<Return>", login)
entry_pass.pack(side=TOP)
check_remember = tk.Checkbutton(auth_frame, font=10, fg='black', text='Remember me', variable=var)
check_remember.pack(side=TOP, anchor=S)
button_login = tk.Button(auth_frame, text="LOGIN", bg='#2E8B57', width=11, command=lambda: login())
button_login.pack(side=LEFT, pady=3, anchor=CENTER)
button_reg = tk.Button(auth_frame, text="REGISTER", bg='#2E8B57', width=11, command=lambda: register())
button_reg.pack(side=RIGHT, pady=3, anchor=CENTER)
# endregion
# region main menu
main_frame = LabelFrame(root, width=850, height=500)
settings_frame = LabelFrame(root, width=600, height=500)
menu_frame = LabelFrame(root, width=150, height=500, relief=FLAT)
button_chat = tk.Button(menu_frame, text="CHAT", bg='#2E8B57', width=17, command=lambda: menu_navigation("chat"))
button_chat.pack(side=TOP, anchor=N)
button_info = tk.Button(menu_frame, text="INFO", bg='#A9A9A9', width=17, command=lambda: menu_navigation("info"))
button_info.pack(side=TOP, pady=5, anchor=N)
button_settings = tk.Button(menu_frame, text="SETTINGS", bg='#A9A9A9', width=17, command=lambda: menu_navigation("set"))
button_settings.pack(side=TOP, anchor=N)
button_logout = tk.Button(menu_frame, text="LOGOUT", bg='#A9A9A9', width=17, command=lambda: logout())
button_logout.pack(side=TOP, pady=5, anchor=N)
main2_frame = LabelFrame(main_frame, width=600, height=350, relief=FLAT)
main2_frame.pack(side=TOP, anchor=CENTER)
# endregion

# region chat
frame = Frame(main2_frame, width=850, height=500)
frame.pack(expand=True, fill=BOTH)
canvas = Canvas(frame, bg='#FFFFFF', width=850, height=410, scrollregion=(0, 0, 500, 500))
vbar = Scrollbar(frame, orient=VERTICAL)
vbar.pack(side=RIGHT, fill=Y)
vbar.config(command=canvas.yview)
hbar = Scrollbar(frame, orient=HORIZONTAL)
hbar.pack(side=BOTTOM, fill=X)
hbar.config(command=canvas.xview)
canvas.config(width=850, height=410)
canvas.config(xscrollcommand=hbar.set, yscrollcommand=vbar.set)
canvas.pack(side=TOP, expand=True, fill=BOTH)
canvas.bind("<MouseWheel>", OnMouseWheel)
canvas.config(scrollregion=canvas.bbox("all"))
button_refresh = tk.Button(main_frame, text="REFRESH", bg='#2E8B57', width=128, command=lambda: get_message())
button_refresh.pack(side=TOP, pady=3, anchor=CENTER)
entry_id = tk.Entry(main_frame, font=10, width=8)
entry_id.bind("<Return>", send_message_handler)
entry_id.pack(side=LEFT, padx=5)
entry_msg = tk.Entry(main_frame, font=10, width=75)
entry_msg.bind("<Return>", send_message_handler)
entry_msg.pack(side=LEFT, padx=3)
button_img = tk.Button(main_frame, text="➕", bg='#2E8B57', width=3, command=lambda: send_image())
button_img.pack(side=LEFT, anchor=E)
button_send = tk.Button(main_frame, text="SEND", bg='#2E8B57', width=8, command=lambda: send_message())
button_send.pack(side=LEFT, anchor=E, padx=3)
entry_log.focus_set()
# root.after(500, loop)
# endregion
# region settings
settings_frame1 = LabelFrame(settings_frame, width=850, height=410, relief=FLAT)
settings_frame1.pack(side=TOP, pady=2, anchor=N)
label_font = tk.Label(settings_frame1, font=10, text="  Text font:", fg="black", width=18, anchor=W)
label_font.pack(side=LEFT, anchor=W)
entry_font = tk.Entry(settings_frame1, font=12, width=20, fg="black")
entry_font.pack(side=LEFT, padx=170, anchor=CENTER)
button_font = tk.Button(settings_frame1, text="SET", bg='#2E8B57', width=15, command=lambda: change_text_font())
button_font.pack(side=RIGHT, anchor=E)
settings_frame2 = LabelFrame(settings_frame, width=600, height=25, relief=FLAT)
settings_frame2.pack(side=TOP, pady=2, anchor=N)
label_b_font = tk.Label(settings_frame2, font=10, text="  Buttons font:", fg="black", width=18, anchor=W)
label_b_font.pack(side=LEFT, anchor=W)
entry_b_font = tk.Entry(settings_frame2, font=12, width=20, fg="black")
entry_b_font.pack(side=LEFT, padx=170, anchor=CENTER)
button_b_font = tk.Button(settings_frame2, text="SET", bg='#2E8B57', width=15, command=lambda: change_but_font())
button_b_font.pack(side=RIGHT, anchor=E)
settings_frame_2 = LabelFrame(settings_frame, width=600, height=25, relief=FLAT)
settings_frame_2.pack(side=TOP, pady=2, anchor=N)
label_check = tk.Label(settings_frame_2, font=10, text="  Update frequency:", fg="black", width=18, anchor=W)
label_check.pack(side=LEFT, anchor=W)
label_check2 = tk.Label(settings_frame_2, font=12, width=20, fg="black")
label_check2.pack(side=LEFT, padx=170, anchor=CENTER)
button_check = tk.Button(settings_frame_2, text="10 Min", bg='#2E8B57', width=15, command=lambda: auto_check())
button_check.pack(side=RIGHT, anchor=E)
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
label_info = tk.Label(main1_frame, font=10, text="ID/Nickname", fg="black", width=18)
label_info.pack(side=TOP, anchor=CENTER)
entry_res = tk.Entry(main1_frame, font=10, width=20, state='disabled')
entry_res.pack(side=TOP, padx=2, pady=3, anchor=CENTER)
entry_id_or_nick = tk.Entry(main1_frame, font=10, width=20)
entry_id_or_nick.pack(side=TOP, padx=2, anchor=CENTER)
button_check = tk.Button(main1_frame, text="CHECK", bg='#2E8B57', width=25, command=lambda: get_user_info())
button_check.pack(side=TOP, anchor=CENTER)
# endregion

labels = [label_user, label_password, entry_id, entry_msg, label_old_pass, entry_old_pass, entry_id_or_nick,
          label_info, entry_res, entry_new_pass, label_new_pass, entry_font, entry_b_font, label_font, label_b_font]
buttons = []
auto_login()

if __name__ == "__main__":
    root.title("Chat")
    root.geometry("200x160+{}+{}".format(w, h))
    root.resizable(False, False)
    root.mainloop()
