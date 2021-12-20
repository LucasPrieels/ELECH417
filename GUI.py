import tkinter as tk
from tkinter import scrolledtext

global font
font = "Arial Black"
usr = "nico"
user_to = "nico"

root = tk.Tk()
def chat_init_gui():
    global root
    root.destroy()
    root = tk.Tk()
    root.title('Chat')
    root.geometry('600x400')
    root.configure(bg='white')
    root.resizable(False, False)

    tk.Label(root, text='Chat', bg='white', font=(font, 13),fg = 'black', width=50, height=1).place(x=-200, y=20)
    text = scrolledtext.ScrolledText(root, height=17, width=41, font=(font, 10), wrap='word')
    text.place(x=10, y=40)
    text.yview(tk.END)
    text.configure(state=tk.NORMAL)

    text.insert(tk.INSERT, "J'adore les gros chibre" + '\n')
    text.insert(tk.INSERT, "J'adore les gros chibre")
    text.configure(state=tk.DISABLED)



    msg_entry = tk.Entry(root, font=(font, 13), width=25)

    msg_entry.place(x=10, y=365)

    send = tk.Button(root, font=(font, 10), text='Send', bd=0, bg='blue', fg='black', width=10,
                     command=lambda: print("envoyer message"))
    send.place(x=300, y=365)

    tk.Label(root, font=(font, 13), bg='blue', fg='black', text="send to " + user_to, width=12).place(y=40, x=400)

    tk.Label(root, font=(font, 13), bg='Green', fg='black', text='Users', width=10).place(y=200, x=400)

    active_users = tk.Listbox(root, height=8, width=20)
    active_users.place(x=400, y=230)

    tk.Label(root, text='Logged In as : \n' + usr, font=(font, 10)).place(x=400, y=360)

    root.mainloop()


chat_init_gui()