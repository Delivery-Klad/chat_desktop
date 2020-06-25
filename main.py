import psycopg2
import bcrypt
import tkinter as tk
from tkinter import *
from tkinter import messagebox


root = tk.Tk()
w = root.winfo_screenwidth() // 2 - 500
h = root.winfo_screenheight() // 2 - 150
crypt_step = 12
user_login = ''
user_id = ''


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
        cursor.execute('CREATE TABLE IF NOT EXISTS users(id INTEGER,' 
                       'login TEXT,'
                       'password TEXT)')
        cursor.execute('CREATE TABLE IF NOT EXISTS messages(from_id INTEGER,'
                       'to_id INTEGER,'
                       'message TEXT)')
        connect.commit()
        cursor.close()
        connect.close()
    except Exception as e:
        exception_handler(e, connect, cursor)


def login():
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
        except Exception as e:
            exception_handler(e, connect, cursor)
            messagebox.showerror('Input error', 'User not found')
            return
        user_login = entry_log.get()
        user_id = get_id(cursor)
        get_message()
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
        for i in entry_pass.get():
            if ord(i) < 45 or ord(i) > 122:
                messagebox.showerror('Input error', 'Unsupported symbols')
                cursor.close()
                connect.close()
                return
        for i in entry_log.get():
            if ord(i) < 45 or ord(i) > 122:
                messagebox.showerror('Input error', 'Unsupported symbols')
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
        cursor.execute("INSERT INTO users VALUES ({0}, '{1}', '{2}')".format(max_id, entry_log.get(), hashed_pass))
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
    auth_frame.pack_forget()
    root.geometry("600x270+{}+{}".format(w, h))
    main_frame.pack(side=TOP, anchor=CENTER)


def get_user_info():
    connect, cursor = pg_connect()
    try:
        if entry_id_or_nick.get().isdigit():
            res = get_user_nickname(int(entry_id_or_nick.get()), cursor)
        else:
            res = get_user_id(entry_id_or_nick.get(), cursor)
        cursor.close()
        connect.close()
        if res == 0:
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
        return 0
    except Exception as e:
        print(e)


def get_user_id(user, cursor):
    try:
        cursor.execute("SELECT id FROM users WHERE login='{0}'".format(user))
        res = cursor.fetchall()
        return res[0][0]
    except IndexError:
        return 0
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
        encrypt_msg = encrypt(to_id, int(user_id), msg)
        cursor.execute("INSERT INTO messages VALUES ({0}, {1}, '{2}')".format(user_id, to_id, encrypt_msg))
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
            decrypt_msg = decrypt(int(i[0]), int(user_id), i[2])
            nickname = get_user_nickname(i[0], cursor)
            content = '{0}: {1}'.format(nickname, decrypt_msg)
            list_box2.insert(tk.END, content)
        cursor.close()
        connect.close()
    except Exception as e:
        exception_handler(e, connect, cursor)


def encrypt(to_id: int, users_id: int, message: str):
    global crypt_step
    encrypt_message = ''
    try:
        local_step = abs(to_id - users_id) % 20 + 300
        for i in range(len(message)):
            if i % 2 == 0:
                encrypt_message += chr(ord(message[i]) + local_step)
            else:
                encrypt_message += chr(ord(message[i]) + crypt_step)
        return encrypt_message
    except Exception as e:
        print(e)


def decrypt(to_id: int, users_id: int, message: str):
    global crypt_step
    decrypt_message = ''
    try:
        local_step = abs(to_id - users_id) % 20 + 300
        for i in range(len(message)):
            if i % 2 == 0:
                decrypt_message += chr(ord(message[i]) - local_step)
            else:
                decrypt_message += chr(ord(message[i]) - crypt_step)
        return decrypt_message
    except Exception as e:
        print(e)


create_tables()

# region auth
auth_frame = LabelFrame(root, width=200, height=130, relief=FLAT)
auth_frame.pack(side=TOP, anchor=CENTER)
label_rep = tk.Label(auth_frame, font=10, text="Username:                       ", fg="black", width=18)
label_rep.pack(side=TOP, anchor=S)
entry_log = tk.Entry(auth_frame, font=12, width=20, fg="black")
entry_log.pack(side=TOP)
label_rep = tk.Label(auth_frame, font=10, text="Password:                       ", fg="black", width=18)
label_rep.pack(side=TOP, anchor=S)
entry_pass = tk.Entry(auth_frame, font=12, width=20, fg="black", show='*')
entry_pass.pack(side=TOP)
button_login = tk.Button(auth_frame, text="LOGIN", bg='#2E8B57', width=11, command=lambda: login())
button_login.pack(side=LEFT, pady=2, anchor=CENTER)
button_reg = tk.Button(auth_frame, text="REGISTER", bg='#2E8B57', width=11, command=lambda: register())
button_reg.pack(side=RIGHT, pady=2, anchor=CENTER)
# endregion

# region main menu
main_frame = LabelFrame(root, width=600, height=350)
main2_frame = LabelFrame(main_frame, width=600, height=350, relief=FLAT)
main2_frame.pack(side=TOP, anchor=CENTER)
main1_frame = LabelFrame(main2_frame, width=600, height=350, relief=SUNKEN)
main1_frame.pack(side=LEFT, anchor=CENTER)
label_rep = tk.Label(main1_frame, font=10, text="ID/Nickname", fg="black", width=18)
label_rep.pack(side=TOP, anchor=CENTER)
entry_res = tk.Entry(main1_frame, font=10, width=20, state='disabled')
entry_res.pack(side=TOP, padx=2, pady=3, anchor=CENTER)
entry_id_or_nick = tk.Entry(main1_frame, font=10, width=20)
entry_id_or_nick.pack(side=TOP, padx=2, anchor=CENTER)
button_check = tk.Button(main1_frame, text="CHECK", bg='#2E8B57', width=25, command=lambda: get_user_info())
button_check.pack(side=TOP, anchor=CENTER)
list_box2 = Listbox(main2_frame, selectmode=EXTENDED, font=10, width=50, height=10, fg="black")
list_box2.pack(side=LEFT)

button_refresh = tk.Button(main_frame, text="REFRESH", bg='#2E8B57', width=85, command=lambda: get_message())
button_refresh.pack(side=TOP, pady=3, anchor=CENTER)
entry_id = tk.Entry(main_frame, font=10, width=8)
entry_id.pack(side=LEFT, padx=2)
entry_msg = tk.Entry(main_frame, font=10, width=50)
entry_msg.pack(side=LEFT, padx=2)
button_send = tk.Button(main_frame, text="SEND", bg='#2E8B57', width=7, command=lambda: send_message())
button_send.pack(side=LEFT, anchor=E)
# endregion

if __name__ == "__main__":
    root.title("Chat")
    root.geometry("200x130+{}+{}".format(w, h))
    root.resizable(False, False)
    root.mainloop()
