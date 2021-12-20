#!/usr/bin/python3

import socket, time
from _thread import *
import tkinter as tk
from tkinter import scrolledtext
font = "Arial Black"
disconnection = False # It is put to True when the user wants to be disconnected


def connect_to_server(ip, remote_port):
    s = socket.socket() # Remote socket
    host = socket.gethostname() # Remote address (here same as local since local tests)
    if ip == "-1": # If local
        ip = host
    print("Remote port : " + str(remote_port))

    s.connect((ip, remote_port))
    return s


def check_credentials(usr, pswd):
    if len(usr) == 0:
        return False;
    elif (usr[0]).isdigit() or len(usr) > 10: # A username can't start with a digit or be longer than 10 characters
        return False
    return True


def listen_for_messages(): # Listen from messages from the server and displays them
    sender = bytes.decode(server_main_socket.recv(10))
    while True:
        if disconnection: # If the user wants to be disconnected we stop receiving data for this user
            print("Disconnection")
            return
        data = bytes.decode(server_main_socket.recv(2048))
        print("From user " + sender + " : " + data)

#GUI

def init_gui():
    global root
    root = tk.Tk()
    root.geometry('400x150')
    root.title('login signup')

    tk.Button(root, text="Login", command=login_gui).grid(row=4, column=0)
    tk.Button(root, text="Register", command=register_gui).grid(row=4, column=2)

    root.mainloop()


def login_gui():
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

    def login(ip):
        global usr
        global server_listen_socket

        usr = user_entry.get()
        pswd = pass_entry.get()

        server_main_socket = connect_to_server(ip, 10000)  # The server port number to connect is 10000
        server_main_socket.send(str.encode("0"))  # Code stating we want to login
        server_main_socket.send(str.encode(str(usr) + " " + str(pswd)))  # str.encode() to transform the string into bytes

        ans = bytes.decode(server_main_socket.recv(1))  # 1 byte is enough
        if ans == "0":
            resp.configure(text="username unknown", fg='red')
        elif ans == "1":
            resp.configure(text="incorrect password", fg='red')
        elif ans == "2":
            resp.configure(text=f'Login Successful\n Welcome {usr} ', fg='green')
            remote_port = bytes.decode(server_main_socket.recv(
                4))  # 4 bytes for a port number between 2000 and 3000 (in string format so each character takes a byte)
            server_listen_socket = connect_to_server(ip,int(remote_port))  # Connect to the new port specific for this client, given by the server
            chat_init_gui()
        else:
            raise Exception("Unexpected answer")

    submit = tk.Button(root, text='Submit', font=(font, 10, 'bold'), width=14, bg='green', command= lambda: login(ip), fg='black')
    submit.place(x=10, y=180)

    tk.Label(root, text='Don\'t Have An Account ?', bg='white', font = (font, 10, "normal")).place(x=30, y=210)

    tk.Button(root, text='Register', font=(font, 10, 'underline'), bg='white', fg='blue', command = register_gui).place(x=200, y=210)

    resp = tk.Label(root, text='', font=('Arial Black', 10, 'bold'), bg='white')
    resp.place(x=10, y=250)

    root.mainloop()


def chat_init_gui():
    global root
    global usr
    global user_to
    user_to = usr # juste pour tester
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

    def receive():  # Listen from messages from the server and displays them
        user_from = bytes.decode(server_main_socket.recv(10))
        data = bytes.decode(server_main_socket.recv(2048))
        text.configure(state=tk.NORMAL)
        text.insert(tk.INSERT, '['+user_from+']','name')
        text.insert(tk.INSERT, data+"\n",'message')
        text.tag_config('name', foreground="green",font = (font, 14, 'bold'))
        text.tag_config('message', foreground="green")
        text.configure(state=tk.DISABLED)

    def send():  # Listen for the client's input and sends it to the server
        data = msg_entry.get()
        server_listen_socket.send(str.encode(data))  # Send message
        print("message envoyé")
        msg_entry.delete(0, 'end')




    sendbutton = tk.Button(root, font=(font, 10), text='Send', bd=0, bg='blue', fg='black', width=10,
                     command=send)
    sendbutton.place(x=300, y=365)

    tk.Label(root, font=(font, 13), bg='blue', fg='black', text="send to " + user_to, width=12).place(y=40, x=400)

    tk.Label(root, font=(font, 13), bg='Green', fg='black', text='Users', width=10).place(y=200, x=400)

    active_users = tk.Listbox(root, height=8, width=20)
    active_users.place(x=400, y=230)

    tk.Label(root, text='Logged In as : \n' + usr, font=(font, 10)).place(x=400, y=360)



    root.mainloop()



def register_gui():
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

    def signup(ip):
        global server_main_socket
        usr = user_entry.get()
        pswd = pass_entry.get()

        if not check_credentials(usr, pswd):
            resp.configure(text="A username can't start with a digit or be longer than 10 characters",  wraplength=200, fg='red')
        else:
            server_main_socket = connect_to_server(ip, 10000)  # The server port number to connect is 10000

            server_main_socket.send(str.encode("1"))  # Code stating we want to sign up
            server_main_socket.send(
                str.encode(str(usr) + " " + str(pswd)))  # str.encode() to transform the string into bytes

            ans = bytes.decode(server_main_socket.recv(1))  # 1 byte is enough, it's the status of the query
            if ans == "0":
                resp.configure(text='Username already used',  wraplength=200, fg='red')

            elif ans == "1":
                resp.configure(text='Signup succesfull !',  wraplength=200, fg='green')
            else:
                raise Exception("Unexpected answer")


    submit = tk.Button(root, text='Submit', font=(font, 10, 'bold'), width=14, bg='green', command = lambda:signup(ip),
                       fg='black')
    submit.place(x=10, y=180)

    tk.Label(root, text='Already Have an account ?', bg='white', font=(font, 10, "normal")).place(x=30, y=210)

    tk.Button(root, text='login', font=(font, 10, 'underline'), bg='white', fg='blue',
              command=login_gui).place(x=200, y=210)

    root.bind('<Return>', init_gui)

    root.mainloop()




#try:
ip = "-1" # 192.168.1.30" # IP address of the remote server, or -1 for local
init_gui()


#
#start_new_thread(listen_for_input, ()) # Thread that listens to the client's inputs and sends them to their recipient
#start_new_thread(listen_for_messages, ()) # Thread that listens to the inputs from the server or other clients and displays them
# while not disconnection: # While the user doesn't want to be disconnected, we wait

