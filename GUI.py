import tkinter as tk
from tkinter import scrolledtext

global font
font = "Comic Sans Ms"


def login():
    global root
    root.destroy()
    root = tk.Tk()

    root.title('Login')
    root.geometry('300x300+220+170')
    root.configure(bg='white')
    root.resizable(False, False)

    log_label = tk.Label(root, text='Login', width=20, height=1, font=(font, 20, 'bold'))
    log_label.pack()

    u = tk.Label(root, text='Username :', font=(font, 14, 'bold'), bg='white')
    u.place(x=10, y=50)

    user_entry = tk.Entry(root, font=(font, 10, 'bold'), width=25, bg='powder blue')
    user_entry.place(x=10, y=80)

    p = tk.Label(root, text='Password :', font=(font, 14, 'bold'), bg='white')
    p.place(x=10, y=110)

    pass_entry = tk.Entry(root, show='*', font=(font, 10, 'bold'), width=25, bg='powder blue')
    pass_entry.place(x=10, y=140)

    resp = tk.Label(root, text='', font=(font, 10, 'bold'), bg='white')
    resp.place(x=10, y=250)

    submit =tk.Button(root, text='Submit', font=(font, 10, 'bold'), width=14, bg='green', command=lambda: print((pass_entry.get() + user_entry.get())), fg='black')
    submit.place(x=10, y=180)

    tk.Label(root, text='Don\'t Have An Account ?', bg='white', font = (font, 10, "normal")).place(x=30, y=210)

    tk.Button(root, text='Register', font=(font, 10, 'underline'), bg='white', fg='blue', command = register).place(x=200, y=210)


    root.mainloop()


def register():
    global root
    root.destroy()
    root = tk.Tk()

    root.title('Register')
    root.geometry('300x300+220+170')
    root.configure(bg='white')
    root.resizable(False, False)

    log_label = tk.Label(root, text='Register', width=20, height=1, font=(font, 20, 'bold'))
    log_label.pack()

    u = tk.Label(root, text='Username :', font=(font, 14, 'bold'), bg='white')
    u.place(x=10, y=50)

    user_entry = tk.Entry(root, font=(font, 10, 'bold'), width=25, bg='powder blue')
    user_entry.place(x=10, y=80)

    p = tk.Label(root, text='Password :', font=(font, 14, 'bold'), bg='white')
    p.place(x=10, y=110)

    pass_entry = tk.Entry(root, show='*', font=(font, 10, 'bold'), width=25, bg='powder blue')
    pass_entry.place(x=10, y=140)

    resp = tk.Label(root, text='', font=(font, 10, 'bold'), bg='white')
    resp.place(x=10, y=250)

    submit = tk.Button(root, text='Submit', font=(font, 10, 'bold'), width=14, bg='green', command=log_func,
                       fg='black')
    submit.place(x=10, y=180)

    tk.Label(root, text='Already Have an account ?', bg='white', font=(font, 10, "normal")).place(x=30, y=210)

    tk.Button(root, text='login', font=(font, 10, 'underline'), bg='white', fg='blue',
              command=login).place(x=200, y=210)

    root.bind('<Return>', init)

    root.mainloop()


def chat():
    root.destroy()
    win = tk.Toplevel()
    win.geometry('530x400')
    win.resizable(False, False)
    win.title(f'Chat_username')

    tk.Label(win, text='Chat', bg='white', font=('arial black', 13), width=50, height=1).pack()

    text = scrolledtext.ScrolledText(win, height=17, width=41, font=('arial black', 10), wrap="word")
    text.place(x=10, y=40)
    text.yview('end')

    msg_entry = tk.Entry(win, font=('arial black', 13), width=25)
    msg_entry.place(x=10, y=365)

    send = tk.Button(win, font=('arial black', 10), text='Send', bd=0, bg='blue', fg='white', width=10)
    send.place(x=300, y=365)

    tk.Label(win, font=('arial black', 13), bg='blue', fg='white', text='Users', width=12).place(y=40, x=400)


def log_func():
    print("zeubi")


def init():
    global root
    root = tk.Tk()
    root.geometry('400x150')
    root.title('login signup')

    tk.Button(root, text="Login", command=login).grid(row=4, column=0)
    tk.Button(root, text="Register", command=register).grid(row=4, column=2)

    root.mainloop()


init()