# import requests

# dbx = dropbox.Dropbox('eCp2HTOUrNUAAAAAAAAAASLGV_nwg-uK-KcCXkZTWnT66l2rg9-W6CAGKZnMTiLI')

# result = dbx.sharing_create_shared_link_with_settings('/test.txt')

# print(result.url)
# import yadisk
# y = yadisk.YaDisk(token="AgAAAABITC7sAAav1g3D_G43akSwv85Xg-yPrCY")
# y.upload("test.txt", "/destination.txt")
# print(y.get_download_link('/destination.txt'))
# print(y.get_disk_info())

from tkinter import *
from tkinter import ttk

ws = Tk()
style = ttk.Style()
style.configure("mystyle", highlightthickness=0, background='grey', bd=0, font=('Calibri', 11))
style.theme_use("clam")
style.configure("mystyle.Heading", background='grey', relief='flat', font=('Calibri', 13, 'bold'))
style.layout("mystyle", [('mystyle.treearea', {'sticky': 'nswe'})])
canvas_users = ttk.Treeview(ws, columns=(1, 2, 3), show='headings', height=8, style="mystyle")
canvas_users.pack()
canvas_users.heading(1, text="ID", anchor=W)
canvas_users.heading(2, text="Username", anchor=W)
canvas_users.heading(3, text="Last activity", anchor=W)
canvas_users.column(1, width=50, stretch=NO)
canvas_users.column(2, width=350)
canvas_users.column(3, width=110, stretch=NO)
canvas_users.tag_configure('bb', background='grey', foreground='white')


def update_item():
    for i in canvas_users.get_children():
        canvas_users.delete(i)


canvas_users.insert(parent='', index=END, values=("0", "ggdfgdgd", 1000000.00), tags=('bb',))
canvas_users.insert(parent='', index=END, values=("1", "dfgdgdgdgfd", 120000.00), tags=('bb',))
canvas_users.insert(parent='', index=END, values=("2", "dgdfgdgfdgfd", 41000.00), tags=('bb',))
canvas_users.insert(parent='', index=END, values=("3", "edgfdfgdfgdgdgf14", 22000.00), tags=('bb',))
ws.mainloop()
