import psycopg2
import tkinter as tk
from tkinter import *
from tkinter import messagebox


root = tk.Tk()
user_login = ''
user_id = ''


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
    try:
        connect, cursor = pg_connect()
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
        print(e)


def login():
    global user_login
    global user_id
    try:
        if len(entry_log.get()) == 0 or len(entry_pass.get()) == 0:
            messagebox.showerror('Input error', 'Fill all input fields')
            return
        connect, cursor = pg_connect()
        try:
            cursor.execute("SELECT password FROM users WHERE login='{0}'".format(entry_log.get()))
            res = cursor.fetchall()[0][0]
            if res != entry_pass.get():
                cursor.close()
                connect.close()
                messagebox.showerror('Input error', 'Wrong password')
                return
        except Exception as e:
            print(e)
            cursor.close()
            connect.close()
            messagebox.showerror('Input error', 'User not found')
            return
        user_login = entry_log.get()
        user_id = get_id(cursor)
        get_message()
        hide_auth_menu()
        cursor.close()
        connect.close()
    except Exception as e:
        print(e)


def register():
    try:
        if len(entry_log.get()) == 0 or len(entry_pass.get()) == 0:
            messagebox.showerror('Input error', 'Fill all input fields')
            return
        connect, cursor = pg_connect()
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

        cursor.execute("SELECT MAX(id) FROM users")
        max_id = cursor.fetchall()[0][0]
        if max_id is not None:
            max_id += 1
        else:
            max_id = 0
        cursor.execute("INSERT INTO users VALUES ({0}, '{1}', '{2}')".format(max_id, entry_log.get(), entry_pass.get()))
        connect.commit()
        cursor.close()
        connect.close()
    except Exception as e:
        print(e)


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
    main_frame.pack(side=TOP, pady=50, anchor=CENTER)


def get_nickname(user, cursor):
    try:
        cursor.execute("SELECT login FROM users WHERE id={0}".format(user))
        res = cursor.fetchall()
        return res[0][0]
    except Exception as e:
        print(e)


def send_message():
    global user_id
    try:
        if len(entry_id.get()) == 0 or len(entry_msg.get()) == 0:
            messagebox.showerror('Input error', 'Fill all input fields')
            return
        to_id = int(entry_id.get())
        msg = entry_msg.get()
        connect, cursor = pg_connect()
        cursor.execute("INSERT INTO messages VALUES ({0}, {1}, '{2}')".format(user_id, to_id, msg))
        connect.commit()
        cursor.close()
        connect.close()
    except Exception as e:
        print(e)


def get_message():
    global user_id
    try:
        connect, cursor = pg_connect()
        cursor.execute("SELECT * FROM messages WHERE to_id={0}".format(user_id))
        res = cursor.fetchall()
        cursor.execute("DELETE FROM messages WHERE to_id={0}".format(user_id))
        connect.commit()
        for i in res:
            nickname = get_nickname(i[0], cursor)
            content = nickname + ': ' + str(i[2])
            list_box2.insert(tk.END, content)
        cursor.close()
        connect.close()
    except Exception as e:
        print(e)


create_tables()

# region auth
auth_frame = LabelFrame(root, width=925, height=250)
auth_frame.pack(side=TOP, pady=150, anchor=CENTER)
label_rep = tk.Label(auth_frame, font=10, text="Username:                       ", fg="black", width=18)
label_rep.pack(side=TOP, anchor=S)
entry_log = tk.Entry(auth_frame, font=12, width=20, fg="black")
entry_log.pack(side=TOP)
label_rep = tk.Label(auth_frame, font=10, text="Password:                       ", fg="black", width=18)
label_rep.pack(side=TOP, anchor=S)
entry_pass = tk.Entry(auth_frame, font=12, width=20, fg="black")
entry_pass.pack(side=TOP)
button_login = tk.Button(auth_frame, text="login", bg='#2E8B57', width=10, command=lambda: login())
button_login.pack(side=LEFT, anchor=CENTER)
button_reg = tk.Button(auth_frame, text="register", bg='#2E8B57', width=10, command=lambda: register())
button_reg.pack(side=RIGHT, anchor=CENTER)
# endregion

# region main menu
main_frame = LabelFrame(root, width=800, height=350)
list_box2 = Listbox(main_frame, selectmode=EXTENDED, font=10, width=50, height=10, fg="black")
list_box2.pack(side=TOP)
button_send = tk.Button(main_frame, text="refresh", bg='#2E8B57', width=50, command=lambda: get_message())
button_send.pack(side=TOP)
entry_id = tk.Entry(main_frame, font=10, width=8)
entry_id.pack(side=LEFT, padx=2)
entry_msg = tk.Entry(main_frame, font=10, width=34)
entry_msg.pack(side=LEFT, padx=2)
button_send = tk.Button(main_frame, text="send", bg='#2E8B57', width=8, command=lambda: send_message())
button_send.pack(side=LEFT, anchor=E)
# endregion

w = root.winfo_screenwidth() // 2 - 500
h = root.winfo_screenheight() // 2 - 150
if __name__ == "__main__":
    root.title("Chat")
    root.geometry("920x427+{}+{}".format(w, h))
    root.resizable(False, False)
    root.mainloop()
