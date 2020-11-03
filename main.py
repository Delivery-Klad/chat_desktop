import os
import rsa
import bcrypt
import base64
import random
import psycopg2
import tkinter as tk
from tkinter import *
from tkinter import messagebox
from tkinter import filedialog
from PIL import Image as image1
from PIL import ImageTk as image2
import keyring
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime, timezone

from keyring.backends.Windows import WinVaultKeyring

keyring.set_keyring(WinVaultKeyring())

code = None
chats = {}
current_chat = "g0"
root = tk.Tk()
spacing = 0
w = root.winfo_screenwidth() // 2 - 140
h = root.winfo_screenheight() // 2 - 100
user_login = ''
user_id = ''
email = ''
var = IntVar()
private_key = rsa.PrivateKey(1, 2, 3, 4, 5)
files_dir = 'files'
auto_fill_data_file = files_dir + '/rem.rm'
private_key_file = files_dir + '/priv_key.PEM'
current_chat = -1

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


def debug(cursor):
    cursor.execute("SELECT * FROM chats")
    print(cursor.fetchall())
    cursor.execute("SELECT table_name FROM information_schema.tables WHERE table_schema NOT IN ("
                   "'information_schema', 'pg_catalog') AND table_schema IN('public', 'myschema');")
    print(cursor.fetchall())


def create_tables():
    connect, cursor = pg_connect()
    try:
        # cursor.execute("DROP TABLE messages")
        # cursor.execute("DROP TABLE users")
        # cursor.execute("DROP TABLE chats")
        # debug(cursor)
        cursor.execute('CREATE TABLE IF NOT EXISTS users(id INTEGER,'
                       'login TEXT,'
                       'password TEXT,'
                       'pubkey TEXT,'
                       'email TEXT)')
        cursor.execute('CREATE TABLE IF NOT EXISTS chats(id TEXT,'
                       'name TEXT,'
                       'owner INTEGER)')
        cursor.execute('CREATE TABLE IF NOT EXISTS messages(date TIMESTAMP,'
                       'from_id TEXT,'
                       'to_id TEXT,'
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
    label_loading.place(x=60, y=60)
    root.update()
    global user_login, user_id
    connect, cursor = pg_connect()
    try:
        if len(entry_log.get()) == 0 or len(entry_pass.get()) == 0:
            messagebox.showerror('Input error', 'Fill all input fields')
            label_loading.place_forget()
            return
        res = check_password(cursor, entry_log.get(), entry_pass.get().encode('utf-8'))
        if res == "False":
            cursor.close()
            connect.close()
            msg = messagebox.askquestion('Input error', 'Wrong password, recover?', icon='error')
            if msg == 'yes':
                pass_code()
            label_loading.place_forget()
            return
        elif res == "None":
            cursor.close()
            connect.close()
            messagebox.showerror('Input error', 'User not found')
            label_loading.place_forget()
            return
        if var.get() == 0:
            clear_auto_login()
        else:
            fill_auto_login_file(entry_log.get(), entry_pass.get())
        user_login = entry_log.get()
        user_id = get_id(cursor)
        get_private_key()
        hide_auth_menu()
        cursor.close()
        connect.close()
        label_loading.place_forget()
    except Exception as e:
        label_loading.place_forget()
        exception_handler(e, connect, cursor)


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
    connect, cursor = pg_connect()
    try:
        if len(entry_log.get()) == 0 or len(entry_pass.get()) == 0 or len(entry_email.get()) == 0:
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
        cursor.execute("INSERT INTO users VALUES ({0}, '{1}', '{2}', '{3}', '{4}')".format(max_id, entry_log.get(),
                                                                                           hashed_pass,
                                                                                           keys_generation(),
                                                                                           entry_email.get()))
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
    global w, h
    w -= 200
    auth_frame.pack_forget()
    root.geometry("1000x500+{}+{}".format(w, h))
    entry_msg.focus_set()
    menu_frame.pack(side=LEFT, pady=5, anchor=N)
    main_frame.pack(side=LEFT, anchor=CENTER)


def menu_navigation(menu: str):
    root.update()
    global current_chat, chats
    if menu == "chat":
        for key in chats:
            chats[key].pack_forget()
        button_chat.pack(side=TOP, anchor=N)
        button_info.pack(side=TOP, pady=5, anchor=N)
        button_settings.pack(side=TOP, anchor=N)
        button_groups.pack(side=TOP, pady=5, anchor=N)
        button_logout.pack(side=TOP, anchor=N)
        button_back.pack_forget()
        button_chat.configure(bg="#2E8B57")
        button_info.configure(bg="#A9A9A9")
        button_settings.configure(bg="#A9A9A9")
        button_groups.configure(bg="#A9A9A9")
        main1_frame.pack_forget()
        settings_frame.pack_forget()
        group_frame.pack_forget()
        main_frame.pack(side=LEFT, anchor=CENTER)
        current_chat = "g0"
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
        button_logout.pack_forget()
        button_groups.pack_forget()
        main_frame.pack_forget()
        main1_frame.pack_forget()
        settings_frame.pack_forget()
        connect, cursor = pg_connect()
        groups = get_users_groups(cursor)
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
    global current_chat, chats
    current_chat = gr_id
    print(current_chat)
    for key in chats:
        chats[key].configure(bg='#A9A9A9')
    button.configure(bg="#2E8B57")
    get_chat_message()


def get_user_info():
    connect, cursor = pg_connect()
    try:
        _input = entry_id_or_nick.get()
        if _input.isdigit():
            res = get_user_nickname(int(_input), cursor)
        elif _input[-3:] == '_gr':
            res = get_chat_id(_input)
        else:
            res = get_user_id(_input, cursor)
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
    root.update()
    global user_id, current_chat
    connect, cursor = pg_connect()
    try:
        if len(entry_msg.get()) == 0:
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
        to_id = current_chat
        msg = entry_msg.get()
        cursor.execute("SELECT pubkey FROM users WHERE id={0}".format(to_id))
        res = cursor.fetchall()[0][0]
        encrypt_msg = encrypt(msg.encode('utf-8'), res)
        date = datetime.utcnow().strftime('%y-%m-%d %H:%M:%S')
        cursor.execute(
            "INSERT INTO messages VALUES (to_timestamp('{0}', 'dd-mm-yy hh24:mi:ss'), '{1}', '{2}', {3})".format(date,
                                                                                                                 user_id,
                                                                                                                 to_id,
                                                                                                                 encrypt_msg))
        entry_msg.delete(0, tk.END)
        connect.commit()
        cursor.close()
        connect.close()
    except Exception as e:
        exception_handler(e, connect, cursor)


def send_image():
    root.update()
    global user_id, current_chat
    connect, cursor = pg_connect()
    try:
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
        date = datetime.utcnow().strftime('%d/%m/%y %H:%M:%S')
        cursor.execute("INSERT INTO messages VALUES ('{0}', '{1}', '{2}', "
                       "{3})".format(date, user_id, current_chat, psycopg2.Binary(b64)))
        os.remove('resized_image.png')
        connect.commit()
        cursor.close()
        connect.close()
    except Exception as e:
        exception_handler(e, connect, cursor)


def get_message():
    root.update()
    global user_id, spacing, current_chat
    connect, cursor = pg_connect()
    try:
        cursor.execute("SELECT * FROM messages WHERE to_id='{0}' AND from_id='{1}' AND NOT from_id LIKE 'g%' "
                       "ORDER BY date".format(user_id, current_chat))
        res = cursor.fetchall()
        cursor.execute("SELECT * FROM messages WHERE to_id='{1}' AND from_id='{0}' AND NOT from_id LIKE 'g%' "
                       "ORDER BY date".format(user_id, current_chat))
        res += cursor.fetchall()
        res.sort()
        canvas.delete("all")
        for i in res:
            decrypt_msg = decrypt(i[3])
            nick = get_user_nickname(i[2], cursor)
            if decrypt_msg is None:
                content = '{0} {1}:'.format(i[0], nick)
                widget = Label(canvas, text=content, bg='white', fg='black', font=14)
                canvas.create_window(0, spacing, window=widget, anchor='nw')
                spacing += 25
                canvas.config(scrollregion=canvas.bbox("all"))
                with open('tmp_img.png', 'wb') as file:
                    file.write(base64.b64decode(i[3]))
                im = image1.open('tmp_img.png')
                photo = image2.PhotoImage(im)
                im.close()
                os.remove('tmp_img.png')
                widget = Label(canvas, image=photo, fg='black')
                widget.image = photo
                canvas.create_window(0, spacing, window=widget, anchor='nw')
                spacing += photo.height() + 2
            else:
                content = '{0} {2}: {1}'.format(str(i[0])[2:], decrypt_msg, nick)
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
        fill_auto_login_file(user_login, entry_new_pass.get())
    except Exception as e:
        exception_handler(e, connect, cursor)


def create_chat():
    global user_id
    connect, cursor = pg_connect()
    try:
        name = entry_chat.get()
        if len(name) < 5:
            messagebox.showerror("Input error", "Name lenght must be more than 5 characters")
            cursor.close()
            connect.close()
            return
        if name[-3:] != '_gr':
            messagebox.showerror("Input error", "Name must contain '_gr' in the end")
            cursor.close()
            connect.close()
            return
        for i in name:
            if ord(i) < 45 or ord(i) > 122:
                messagebox.showerror('Input error', 'Unsupported symbols')
                cursor.close()
                connect.close()
                return
        cursor.execute("SELECT table_name FROM information_schema.tables WHERE table_schema NOT IN ("
                       "'information_schema', 'pg_catalog') AND table_schema IN('public', 'myschema');")
        print(cursor.fetchall())
        if ('{0}'.format(name),) in cursor.fetchall():
            messagebox.showerror('Name error', 'Name exists')
            cursor.close()
            connect.close()
            return
        max_id = get_max_chat_id(cursor) + 1
        print(max_id)
        cursor.execute("INSERT INTO chats VALUES ('g{0}', '{1}', {2})".format(max_id, name, user_id))
        cursor.execute('CREATE TABLE IF NOT EXISTS {0}(id INTEGER)'.format(name))
        connect.commit()
        cursor.execute("INSERT INTO {0} VALUES({1})".format(name, user_id))
        connect.commit()
        cursor.close()
        connect.close()
    except Exception as e:
        exception_handler(e, connect, cursor)


def get_chat_id(name: str):
    connect, cursor = pg_connect()
    cursor.execute("SELECT id FROM chats WHERE name='{0}'".format(name))
    group_id = cursor.fetchall()[0][0]
    cursor.close()
    connect.close()
    return group_id


def get_chat_name(group_id: str):
    connect, cursor = pg_connect()
    cursor.execute("SELECT name FROM chats WHERE id='{0}'".format(group_id))
    name = cursor.fetchall()[0][0]
    cursor.close()
    connect.close()
    return name


def get_max_chat_id(cursor):
    cursor.execute("SELECT COUNT(*) FROM chats")
    res = cursor.fetchall()[0]
    res = str(res).split(',', 1)[0]
    return int(str(res)[1:])


def get_chat_users(name: str):
    global user_id
    connect, cursor = pg_connect()
    try:
        cursor.execute("SELECT id FROM {0}".format(name))
        return cursor.fetchall()
    except Exception as e:
        exception_handler(e, connect, cursor)


def get_chat_owner(group_id: str):
    global user_id
    connect, cursor = pg_connect()
    try:
        cursor.execute("SELECT owner FROM chats WHERE id='{0}'".format(group_id))
        res = cursor.fetchall()[0][0]
        cursor.close()
        connect.close()
        return res
    except Exception as e:
        exception_handler(e, connect, cursor)


def send_chat_message():
    global user_id, current_chat
    connect, cursor = pg_connect()
    message = entry_msg2.get()
    try:
        if len(message) == 0:
            messagebox.showerror('Input error', 'Fill all input fields')
            cursor.close()
            connect.close()
            return
        name = get_chat_name(current_chat)
        users = get_chat_users(name)
        for i in users:
            cursor.execute("SELECT pubkey FROM users WHERE id={0}".format(i[0]))
            res = cursor.fetchall()[0][0]
            encrypt_msg = encrypt(message.encode('utf-8'), res)
            date = datetime.utcnow().strftime('%d/%m/%y %H:%M:%S')
            cursor.execute(
                "INSERT INTO messages VALUES ('{0}', '{0}', '{1}', {2})".format(date, current_chat + '_' + str(user_id),
                                                                                i[0], encrypt_msg))
            entry_msg2.delete(0, tk.END)
        connect.commit()
        cursor.close()
        connect.close()
    except Exception as e:
        exception_handler(e, connect, cursor)


def get_chat_message():
    global user_id, spacing, current_chat
    connect, cursor = pg_connect()
    try:
        cursor.execute("SELECT * FROM messages WHERE to_id='{0}' AND from_id LIKE '{1}%' ORDER BY date".format(user_id,
                                                                                                               current_chat))
        res = cursor.fetchall()
        for i in res:
            decrypt_msg = decrypt(i[2])
            nickname = get_user_nickname(i[0].split('_', 1)[1], cursor)
            content = '{0}: {1}'.format(nickname, decrypt_msg)
            widget = Label(canvas_2, text=content, bg='white', fg='black', font=14)
            canvas_2.create_window(0, spacing, window=widget, anchor='nw')
            spacing += 25
        canvas_2.config(scrollregion=canvas_2.bbox("all"))
        cursor.close()
        connect.close()
    except Exception as e:
        exception_handler(e, connect, cursor)


def get_users_groups(cursor):
    try:
        groups = []
        cursor.execute("SELECT name FROM chats")
        res = cursor.fetchall()
        for el in res:
            cursor.execute("SELECT COUNT(id) FROM {0} WHERE id='{1}'".format(el[0], user_id))
            tmp = cursor.fetchall()[0][0]
            if tmp == 1:
                groups.append(el[0])
        return groups
    except Exception as e:
        print(e)


def invite_to_group():
    global user_id
    inv_user = entry_inv_id.get()
    inv_group = entry_gr_toinv.get()
    if len(inv_user) == 0 and len(inv_group) == 0:
        messagebox.showerror('Input error', 'Entries lenght must be more than 0 characters')
        return
    connect, cursor = pg_connect()
    try:
        if user_id != int(get_chat_owner(inv_group)):
            messagebox.showerror('Access error', "You are not chat's owner")
            return
        name = get_chat_name(inv_group)
        cursor.execute("INSERT INTO {0} VALUES({1})".format(name, int(inv_user)))
        connect.commit()
        messagebox.showinfo('Success', "Success")
        cursor.close()
        connect.close()
    except Exception as e:
        exception_handler(e, connect, cursor)


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
    global w, h, code
    try:
        if not entry_code.get() == str(code):
            messagebox.showerror('Input error', 'Incorrect code')
            return
        recovery_frame.pack_forget()
        root.geometry("200x130+{}+{}".format(w, h))
        new_pass_frame.pack(side=TOP, anchor=CENTER)
    except Exception as e:
        print(e)


def set_new_pass():
    global user_login, email
    user_login = entry_log.get()
    connect, cursor = pg_connect()
    try:
        if check_input(entry_new_p2.get(), entry_new_p.get()):
            hashed_pass = bcrypt.hashpw(entry_new_p.get().encode('utf-8'), bcrypt.gensalt())
            hashed_pass = str(hashed_pass)[2:-1]
            cursor.execute("UPDATE users SET password='{0}' WHERE email='{1}'".format(hashed_pass, email))
            connect.commit()
            messagebox.showinfo("Success", "Password has been changed")
            fill_auto_login_file(user_login, entry_new_p.get())
            entry_pass.delete(0, tk.END)
            entry_pass.insert(0, entry_new_p.get())
            root.geometry("200x160+{}+{}".format(w, h))
            new_pass_frame.pack_forget()
            auth_frame.pack(side=TOP, anchor=CENTER)
        cursor.close()
        connect.close()
    except Exception as e:
        exception_handler(e, connect, cursor)


def pass_code():
    global code, user_id, email
    connect, cursor = pg_connect()
    try:
        cursor.execute("SELECT email FROM users WHERE id={0}".format(get_user_id(entry_log.get(), cursor)))
        res = cursor.fetchall()[0][0]
        email = res
        code = random.randint(10000, 99999)
        password = "d8fi2kbfpchos"
        mail_login = "iutnqyyujjskrr@mail.ru"
        url = "smtp.mail.ru"
        server = smtplib.SMTP_SSL(url, 465)
        target = res
        title = "Recovery code"
        text = "Your code: {0}".format(code)
        msg = MIMEMultipart()
        msg['Subject'] = title
        msg['From'] = mail_login
        body = text
        msg.attach(MIMEText(body, 'plain'))
        try:
            server.login(mail_login, password)
            server.sendmail(mail_login, target, msg.as_string())
        except Exception as e:
            messagebox.showerror('Error', str(e))
        messagebox.showinfo('Recovery', 'Recovery code has been sent to your email')
        recovery_menu()
        cursor.close()
        connect.close()
    except Exception as e:
        exception_handler(e, connect, cursor)


def open_chat():
    global current_chat
    chat = entry_chat_id.get()
    connect, cursor = pg_connect()
    if len(chat) == 0 or not chat.isnumeric():
        messagebox.showerror('Input error', 'Chat id must be a number')
        cursor.close()
        connect.close()
        return
    nick = get_user_nickname(int(chat), cursor)
    if nick is not None:
        label_chat_id.configure(text='Current chat with: ' + nick)
    else:
        messagebox.showerror('Input error', 'User not found')
        cursor.close()
        connect.close()
        return
    current_chat = int(chat)
    button_send.configure(state='normal')
    button_img.configure(state='normal')
    canvas.delete("all")
    get_message()
    cursor.close()
    connect.close()


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
button_logout = tk.Button(menu_frame, text="LOGOUT", bg='#A9A9A9', width=17, command=lambda: logout())
button_logout.pack(side=TOP, anchor=N)
button_back = tk.Button(menu_frame, text="BACK", bg='#A9A9A9', width=17, command=lambda: menu_navigation("chat"))
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
button_chat_id = tk.Button(chat_frame, text="OPEN", bg='#2E8B57', width=15, command=lambda: open_chat())
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
button_img = tk.Button(main_frame, text="➕", bg='#2E8B57', width=3, command=lambda: send_image(), state='disabled')
button_img.pack(side=LEFT, anchor=E)
button_send = tk.Button(main_frame, text="SEND", bg='#2E8B57', width=8, command=lambda: send_message(),
                        state='disabled')
button_send.pack(side=LEFT, anchor=E, padx=3)

button_refresh2 = tk.Button(group_frame, text="REFRESH", bg='#2E8B57', width=128, command=lambda: get_chat_message())
button_refresh2.pack(side=TOP, pady=3, anchor=CENTER)
entry_msg2 = tk.Entry(group_frame, font=10, width=85)
# entry_msg2.bind("<Return>", send_chat_message())
entry_msg2.pack(side=LEFT, padx=3)
button_img2 = tk.Button(group_frame, text="➕", bg='#2E8B57', width=3)  # , command=lambda: send_image())
button_img2.pack(side=LEFT, anchor=E)
button_send2 = tk.Button(group_frame, text="SEND", bg='#2E8B57', width=8, command=lambda: send_chat_message())
button_send2.pack(side=LEFT, anchor=E, padx=3)

entry_log.focus_set()
# root.after(500, loop)
# endregion
# region settings
settings_frame_2 = LabelFrame(settings_frame, width=600, height=25, relief=FLAT)
settings_frame_2.pack(side=TOP, pady=2, anchor=N)
label_check = tk.Label(settings_frame_2, font=10, text="  Update frequency:", fg="black", width=18, anchor=W)
label_check.pack(side=LEFT, anchor=W)
label_check2 = tk.Label(settings_frame_2, font=12, width=20, fg="black")
label_check2.pack(side=LEFT, padx=170, anchor=CENTER)
button_check = tk.Button(settings_frame_2, text="10 Min", bg='#2E8B57', width=15, command=lambda: auto_check())
button_check.pack(side=RIGHT, anchor=E)

settings_frame7 = LabelFrame(settings_frame, width=600, height=25, relief=FLAT)
settings_frame7.pack(side=TOP, pady=2, anchor=N)
label_chat = tk.Label(settings_frame7, font=10, text="  Create chat:", fg="black", width=18, anchor=W)
label_chat.pack(side=LEFT, anchor=W)
entry_chat = tk.Entry(settings_frame7, font=12, width=20, fg="black")
entry_chat.pack(side=LEFT, padx=170, anchor=CENTER)
button_c_chat = tk.Button(settings_frame7, text="CREATE", bg='#2E8B57', width=15, command=lambda: create_chat())
button_c_chat.pack(side=RIGHT, anchor=E)

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
label_info = tk.Label(main1_frame, font=10, text="ID/Nickname/Group", fg="black", width=18)
label_info.pack(side=TOP, anchor=CENTER)
entry_res = tk.Entry(main1_frame, font=10, width=20, state='disabled')
entry_res.pack(side=TOP, padx=2, pady=3, anchor=CENTER)
entry_id_or_nick = tk.Entry(main1_frame, font=10, width=20)
entry_id_or_nick.pack(side=TOP, padx=2, anchor=CENTER)
button_check = tk.Button(main1_frame, text="CHECK", bg='#2E8B57', width=25, command=lambda: get_user_info())
button_check.pack(side=TOP, anchor=CENTER)

label_loading = Label(root, font=10, text="LOADING", fg="black", bg="white")
# endregion
auto_login()

if __name__ == "__main__":
    root.title("Chat")
    root.geometry("200x160+{}+{}".format(w, h))
    root.resizable(False, False)
    root.mainloop()
