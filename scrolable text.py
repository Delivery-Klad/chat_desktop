from tkinter import *

root = Tk()
root.geometry('500x500')

field = Text(root, width=25, height=10)
field.pack()

scroll = Scrollbar(command=field.yview)
scroll.pack(side=RIGHT, fill=Y)
field.config(yscrollcommand=scroll.set)

root.mainloop()


canvas = Text(frame, bg='#FFFFFF', width=850, height=370)
scroll = Scrollbar(command=canvas.yview)
scroll.pack(side=RIGHT, fill=Y)
canvas.pack(side=TOP, expand=True, fill=BOTH)

"""hbar = Scrollbar(frame, orient=HORIZONTAL)
hbar.pack(side=BOTTOM, fill=X)
hbar.config(command=canvas.xview)"""
# canvas.config(width=850, height=370)
canvas.config(yscrollcommand=scroll.set)
