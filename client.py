#!/usr/bin/python3

import socket, time, os, hashlib
from _thread import *
import tkinter as tk
from tkinter import scrolledtext
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import datetime
import ast


font = "Arial Black"
disconnection = False # It is put to True when the user wants to be disconnected
symm_keys = {}

def connect_to_server(ip, remote_port):
    s = socket.socket() # Remote socket
    host = socket.gethostname() # Remote address (here same as local since local tests)
    if ip == "-1": # If local
        ip = host
    print("Remote port : " + str(remote_port))

    s.connect((ip, remote_port))
    return s


def check_credentials(usr, pswd):
    if (usr[0]).isdigit() or len(usr) > 10 or len(usr) == 0 or len(pswd) < 3: # A username can't start with a digit or be longer than 10 characters and a pasword can't be shorter than 3 characters
        return False
    return True
    
def transform_string_to_key(public_key_string):
    # Transforms the string version of the public key into a real cryptography public key
    public_key_full = "-----BEGIN PUBLIC KEY-----\n" + public_key_string + "\n-----END PUBLIC KEY-----\n"
    public_key = serialization.load_pem_public_key(
        str.encode(public_key_full),
        backend=default_backend()
    )
    return public_key

def generate_symmetric_key(usr, remote_usr, public_key_string):
    # Generates the symmetric key for the connection with this user
    symm_key = Fernet.generate_key()
    print("Symmetric key for this connection : " + bytes.decode(symm_key))
    
    public_key = transform_string_to_key(public_key_string)
    encrypted_symm_key = public_key.encrypt(
        symm_key, # The message to be encrypted is the symmetric key
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    if not os.path.exists("symmetric_keys_" + usr + ".txt"): # If the file doesn't exist yet, create it
        with open("symmetric_keys_" + usr + ".txt", 'w') as f:
            f.write("")
        
    with open("symmetric_keys_" + usr + ".txt", "a") as f:
        print("Writing user " + remote_usr + " with key " + bytes.decode(symm_key))
        f.write(remote_usr + " " + bytes.decode(symm_key) + "\n")
        symm_keys[usr] = symm_key
        
    return encrypted_symm_key

#GUI

def init_gui():
    global root
    root = tk.Tk()
    root.geometry('400x150')
    root.title('login signup')

    tk.Button(root, text="Login", command=login_gui).grid(row=4, column=0)
    tk.Button(root, text="Register", command=register_gui).grid(row=4, column=2)

    root.mainloop()


def authenticate_nonce(server_main_socket, private_key):
    nonce = server_main_socket.recv(64) # No need to convert in str
    print("Nonce : ", end='')
    print(nonce)
    
    encrypted_private_key_nonce = private_key.sign( # See doc on https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
        nonce,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    print("Encrypted nonce : ", end='')
    print(encrypted_private_key_nonce)
    
    server_main_socket.send(encrypted_private_key_nonce) # No need to encode because already in bytes
    
    a = bytes.decode(server_main_socket.recv(1))
    print(a)
    return a == "1"


def init_contacts(usr):
    if not os.path.exists("symmetric_keys_" + usr + ".txt"): # If the file doesn't exist yet, create it
        with open("symmetric_keys_" + usr + ".txt", 'w') as f:
            f.write("")
    with open("symmetric_keys_" + usr + ".txt", 'r') as f:
        for line in f.readlines():
            contact, symm_key = line.split(' ')
            symm_keys[contact] = symm_key.strip() # Removes newline


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
        global server_main_socket
        global server_listen_socket
        global server_main_socket

        usr = user_entry.get()
        pswd = pass_entry.get()

        server_main_socket = connect_to_server(ip, 10000)  # The server port number to connect is 10000
        server_main_socket.send(str.encode("0"))  # Code stating we want to login
        
        server_main_socket.send(str.encode(usr))
        salt = bytes.fromhex(bytes.decode(server_main_socket.recv(32)))
        pw_hash = hashlib.pbkdf2_hmac("sha256", str.encode(pswd), salt, 100000) # 100 000 is the number of iterations of sha-256
        server_main_socket.send(str.encode(pw_hash.hex()))  # str.encode() to transform the string into bytes
                
        print("Public key sent")
        print(pw_hash.hex() + " " + salt.hex())

        ans = bytes.decode(server_main_socket.recv(1))  # 1 byte is enough
        if ans == "0":
            resp.configure(text="username unknown", fg='red')
        elif ans == "1":
            resp.configure(text="incorrect password", fg='red')
        elif ans == "2":
            if not authenticate_nonce(server_main_socket, get_keys()[0]):
                resp.configure(text="incorrect private key", fg='red')
            else:
                resp.configure(text=f'Login Successful\n Welcome {usr} ', fg='green')
                remote_port = bytes.decode(server_main_socket.recv(
                    4))  # 4 bytes for a port number between 2000 and 3000 (in string format so each character takes a byte)
                server_listen_socket = connect_to_server(ip,int(remote_port))  # Connect to the new port specific for this client, given by the server
                init_contacts(usr)
                print("Contacts : ", end='')
                print(symm_keys)
                #start_new_thread(listen_for_messages, ())
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


def get_history_from_server(username1, username2) :

    # Ask server to show history
    server_listen_socket.send(str.encode("2HISTORY"))
    time.sleep(0.1)
    # Sends the concerned usernames
    server_listen_socket.send(str.encode(username1))
    time.sleep(0.1)
    server_listen_socket.send(str.encode(username2))

    return 


def chat_init_gui():
    global root
    global usr
    global user_to
    
    user_to = usr
    root.destroy()
    root = tk.Tk()
    root.title('Chat')
    root.geometry('600x400')
    root.configure(bg='white')
    root.resizable(False, False)

    tk.Label(root, text='Chat', bg='white', font=(font, 13), fg='black', width=50, height=1).place(x=-200, y=20)
    text = scrolledtext.ScrolledText(root, height=17, width=41, font=(font, 10), wrap='word')
    text.place(x=10, y=40)
    text.yview(tk.END)
    text.configure(state=tk.NORMAL)
    text.configure(state=tk.DISABLED)

    msg_entry = tk.Entry(root, font=(font, 13), width=25)

    msg_entry.place(x=10, y=365)

    def receive():  # Listen from messages from the server and displays them
        while True:
            print("Listening for messages...")
            sender = bytes.decode(server_main_socket.recv(10))
            print("Sender : " + sender)
            if disconnection: # If the user wants to be disconnected we stop receiving data for this user
                print("Disconnection")
                return
            if sender == "1NEW": # Create a new contact
                #server_main_socket.send(str.encode("1")) # Confirmation
                sender = bytes.decode(server_main_socket.recv(10))
                print("Received a 1NEW query from " + sender)
                public_key = bytes.decode(server_main_socket.recv(1024))
                print("Received public key : ", end='')
                print(public_key)
                encrypted_symm_key = generate_symmetric_key(usr, sender, public_key)
                print("Encrypted symmetric key : ", end='')
                print(encrypted_symm_key)
                server_main_socket.send(encrypted_symm_key)
            if sender == "2HISTORY" :
                print("Received history from server : ")
                history = bytes.decode(server_main_socket.recv(2048))
                
                # Translates "history" string into a list, and the stringified tuples into tuples
                history_cleaned = ast.literal_eval(history)
                


                refresh(text, history_cleaned)



            else :
                data = server_main_socket.recv(2048)
                f = Fernet(symm_keys[sender])
                print("Symmetric key for user " + user_to + " : " + symm_keys[sender])
                print("Message to decrypt : ", end='')
                print(data)
                decrypted_message = bytes.decode(f.decrypt(data))
                print("Message decrypted : " + decrypted_message)

                text.configure(state=tk.NORMAL)
                text.insert(tk.INSERT, '[' + sender + ']', 'name')
                text.insert(tk.INSERT, decrypted_message + "\n", 'message')
                text.tag_config('name', foreground="green", font=(font, 14, 'bold'))
                text.tag_config('message', foreground="green")
                text.configure(state=tk.DISABLED)


    def send():  # Listen for the client's input and sends it to the server
        data = msg_entry.get()
        server_listen_socket.send(str.encode(user_to))
        time.sleep(0.1) # to avoid merge of user and data
        f = Fernet(symm_keys[user_to])
        print("Symmetric key for user " + user_to + " : " + symm_keys[user_to])
        print("Message to encrypt : " + data)
        encrypted_message = f.encrypt(str.encode(data))
        print("Message encrypted : ", end='')
        print(encrypted_message)
        server_listen_socket.send(encrypted_message)  # Send message

        text.configure(state=tk.NORMAL)
        text.insert(tk.INSERT, '[to ' + user_to + ']', 'name')
        text.insert(tk.INSERT, data + "\n", 'message')
        text.tag_config('name', foreground="green", font=(font, 14, 'bold'))
        text.tag_config('message', foreground="green")
        text.configure(state=tk.DISABLED)

        print("message envoyé")
        msg_entry.delete(0, 'end')

    sendbutton = tk.Button(root, font=(font, 10), text='Send', bd=0, bg='blue', fg='black', width=10,
                           command=send)
    sendbutton.place(x=300, y=365)

    sendto_label = tk.Label(root, font=(font, 13), bg='blue', fg='black', text=user_to, width=15)
    sendto_label.place(y=40, x=400)

    tk.Label(root, font=(font, 13), bg='Green', fg='black', text='Users', width=10).place(y=200, x=400)

    active_users = tk.Listbox(root, height=8, width=20)
    active_users.place(x=400, y=230)

    tk.Label(root, text='Logged In as : \n' + usr, font=(font, 10)).place(x=400, y=360)

    active_users = tk.Listbox(root, height=8, width=20)
    active_users.place(x=400, y=230)

    ########################################################@

    users = ["Karim", "Mahmoud", "Jean", "julien", "nico", "sami"]
    i = 0

    while i < len(users):
        active_users.insert(i + 1, users[i])
        i += 1

    def callback(event):
        global user_to
        selection = event.widget.curselection()
        if selection:
            index = selection[0]
            data = event.widget.get(index)
            print("Data : " + data)
            #server_listen_socket.send(str.encode(data))
            #print(server_main_socket.recv(1))
            #server_listen_socket.send(str.encode("Ceci est un message de test"))
            time.sleep(0.1)
            if data not in symm_keys:
                print("We don't have a symmetric key for the connection with user " + data)
                print("Sending a 1NEW query")
                server_listen_socket.send(str.encode("1NEW"))
                time.sleep(0.1)
                print("Sending it to user " + data)
                server_listen_socket.send(str.encode(data))
                
                private_key, public_key = get_keys()
                symm_key = get_symmetric_key_from_server(server_main_socket, public_key)
                
                if not os.path.exists("symmetric_keys_" + usr + ".txt"): # If the file doesn't exist yet, create itr
                    with open("symmetric_keys_" + usr + ".txt", 'w') as f:
                        f.write("")
            
                with open("symmetric_keys_" + usr + ".txt", "a") as f:
                    print("Writing user " + data + " with key " + symm_key)
                    f.write(data + " " + symm_key + "\n")
                    symm_keys[data] = symm_key
            
            sendto_label.configure(text=data)
            user_to = sendto_label.cget("text")
            get_history_from_server(username1=usr, username2=user_to)


        else:
            sendto_label.configure(text="")

    ##########################################################

    active_users.bind("<Double-1>", callback)   #Get the user we click on

    user_to = sendto_label.cget("text")         #Update the user we want to talk to

    start_new_thread(receive,())

    root.mainloop()


def generate_keys(): # Source of this function : https://nitratine.net/blog/post/asymmetric-encryption-and-decryption-in-python/

    # Generates the private and public keys
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    
    # Write the private key in private_key.pem
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open('private_key.pem', 'wb') as f:
        f.write(pem)
        
    # Write the public key in public_key.pem
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open('public_key.pem', 'wb') as f:
        f.write(pem)


def get_keys(): # Source of this function : https://nitratine.net/blog/post/asymmetric-encryption-and-decryption-in-python/
    if not os.path.exists("private_key.pem") or not os.path.exists("public_key.pem"):
        print("Asymetric keys don't exist yet, creating them...")
        generate_keys() # Generates the public and private keys and store them into files
    
    with open("private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    
    with open("public_key.pem", "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
        
    return private_key, public_key

    
def read_keys(): # Source of this function : https://nitratine.net/blog/post/asymmetric-encryption-and-decryption-in-python/
    print("Read keys : " + str(os.path.exists("private_key.pem")))
    if not os.path.exists("private_key.pem") or not os.path.exists("public_key.pem"):
        print("Asymetric keys don't exist yet, creating them...")
        generate_keys() # Generates the public and private keys and store them into files
    
    key_file = open("private_key.pem", "r")
    private_key = key_file.read()
    
    key_file = open("public_key.pem", "r")
    public_key = key_file.read()
        
    return private_key, public_key


def refresh(text, history):
    global usr
    text.configure(state=tk.NORMAL)
    print(history)
    text.delete('1.0', tk.END)

    for message in history:
        from_username = message[0]
        to_username = message[1]
        if(usr == from_username) :
            ## we are communicating with the "to"
            key = symm_keys[to_username]
        else :
            ## we are communicating with the "from"
            key = symm_keys[from_username]



        content = message[2]
        time = message[3]

        f = Fernet(key)
        print("content : " + content)
        decrypted_message = bytes.decode(f.decrypt(str.encode(content)))


        text.insert(tk.INSERT, '[' + message[0] + ']', 'name')
        text.insert(tk.INSERT, decrypted_message + "\n", 'message')
        text.tag_config('name', foreground="green", font=(font, 14, 'bold'))
        text.tag_config('message', foreground="green")

    text.configure(state=tk.DISABLED)

def get_symmetric_key_from_server(server_main_socket, public_key):
    encrypted_symm_key = server_main_socket.recv(1024) # The key can stay in bytes, no need to convert in str
    
    print("Got encrypted symm key : ", end='')
    print(encrypted_symm_key)
    
    private_key, public_key = get_keys()
    symm_key = private_key.decrypt(
        encrypted_symm_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    symm_key = bytes.decode(symm_key)
    print("Decrypted symmetric key : " + symm_key)
    
    return symm_key


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
        print("Pswd : " + pswd)

        if not check_credentials(usr, pswd):
            resp.configure(text="A username can't start with a digit or be longer than 10 characters and a pasword can't be shorter than 3 characters",  wraplength=200, fg='red')
        else:
            private_key, public_key = read_keys() # Gets the public and private keys, and creates them if needed
                
            clean_public_key = (public_key.split('-')[10]).strip() # Removes the "-----BEGIN PUBLIC KEY----" and "----END PUBLIC KEY----"
                
            print("Public key : " + public_key)
            print(clean_public_key)
            print("Private key : " + private_key)
            
            server_main_socket = connect_to_server(ip, 10000)  # The server port number to connect is 10000

            server_main_socket.send(str.encode("1"))  # Code stating we want to sign up
            
            salt = os.urandom(16)
            pw_hash = hashlib.pbkdf2_hmac("sha256", str.encode(pswd), salt, 100000) # 100 000 is the number of iterations of sha-256
            server_main_socket.send(

                str.encode(usr + " " + pw_hash.hex() + " " + salt.hex() + " " + clean_public_key))  # str.encode() to transform the string into bytes
                
            print("Public key sent")
            print(pw_hash.hex() + " " + salt.hex())

            ans = bytes.decode(server_main_socket.recv(1))  # 1 byte is enough, it's the status of the query
            if ans == "0":
                resp.configure(text='Username already used',  wraplength=200, fg='red')

            elif ans == "1":
                resp.configure(text='Signup successful !',  wraplength=200, fg='green')
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

