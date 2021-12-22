#!/usr/bin/python3

from contextlib import AbstractContextManager
import socket, time, os, hashlib, datetime, pygame, ast
from _thread import *
import tkinter as tk
from tkinter import scrolledtext
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from datetime import datetime


ip = "-1" # IP address of the remote server, or "-1" for local
font = "Arial Black" # Font of the GUI
disconnection = False # It is put to True when the user wants to be disconnected
symm_keys = {} # List of the symmetric keys for conversations between the current client and all the other clients it already talked to


########## CONNECTION TO THE SERVER ##########


def connect_to_server(ip, remote_port):
    s = socket.socket() # Remote socket
    host = socket.gethostname() # Local address
    if ip == "-1": # If the IP is unspecified, we consider we want to work locally
        ip = host

    s.connect((ip, remote_port))
    return s

def disconnect(): # Client is disconnecting
    global disconnection
    server_listen_socket.send(str.encode("0DISCONNEC")) # Tells the server we're disconnecting
    disconnection = True
    root.destroy()
    
# Asks the server the history of messages in a conversation between username1 and username2
def get_history_from_server(username1, username2) :
    # Ask server to show history
    server_listen_socket.send(str.encode("2HISTORY"))
    time.sleep(0.1)
    # Sends the concerned usernames
    server_listen_socket.send(str.encode(username1))
    time.sleep(0.1)
    server_listen_socket.send(str.encode(username2))
    return
    
def refresh_active_users(active_users, users_list) :
    active_users.delete('0', tk.END)
    i = 0
    while i < len(users_list):
        active_users.insert(i + 1, users_list[i])
        i += 1
    return
    
    
########## SECURITY ##########


def init_contacts(usr): # Creates a dictionnary of contacts from the list of symmetric key stored ina  file
    if not os.path.exists("crypto/symmetric_keys_" + usr + ".txt"): # If the file doesn't exist yet, create it
        with open("crypto/symmetric_keys_" + usr + ".txt", 'w') as f:
            f.write("")
    with open("crypto/symmetric_keys_" + usr + ".txt", 'r') as f:
        for line in f.readlines():
            contact, symm_key = line.split(' ')
            symm_keys[contact] = symm_key.strip() # Removes newline

def check_credentials(usr, pswd): # Check the credentials are valid
    if (usr[0]).isdigit() or len(usr) > 10 or len(usr) == 0 or len(pswd) < 3: # A username can't start with a digit or be longer than 10 characters and a pasword can't be shorter than 3 characters
        return False
    return True

def generate_symmetric_key(usr, remote_usr, public_key_string):
    # Generates the symmetric key for the connection with this user
    symm_key = Fernet.generate_key()
    #print("Symmetric key for this connection : " + bytes.decode(symm_key))
    
    # Encrypts the symmetric key with the public key of the receiver, so that only him can decrypt it
    public_key = transform_string_to_key(public_key_string)
    encrypted_symm_key = public_key.encrypt(
        symm_key, # The message to be encrypted is the symmetric key
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # All the symmetric keys are stored in a file
    
    # If the file doesn't exist yet, we first create it
    if not os.path.exists("crypto/symmetric_keys_" + usr + ".txt"):
        with open("crypto/symmetric_keys_" + usr + ".txt", 'w') as f:
            f.write("")
        
    # Append this key to the end of the file
    with open("crypto/symmetric_keys_" + usr + ".txt", "a") as f:
        f.write(remote_usr + " " + bytes.decode(symm_key) + "\n")
        symm_keys[usr] = symm_key
        
    return encrypted_symm_key
    
def transform_string_to_key(public_key_string):
    # Transforms the string version of the public key into a real cryptography public key
    public_key_full = "-----BEGIN PUBLIC KEY-----\n" + public_key_string + "\n-----END PUBLIC KEY-----\n"
    public_key = serialization.load_pem_public_key(
        str.encode(public_key_full),
        backend=default_backend()
    )
    return public_key
    
# Authenticates to the server by waiting for a nonce, signing it then sending it back
def authenticate_nonce(server_main_socket, private_key):
    nonce = server_main_socket.recv(64)
    
    # Sign the nonce
    encrypted_private_key_nonce = private_key.sign( # See doc on https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
        nonce,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    server_main_socket.send(encrypted_private_key_nonce) # No need to encode because already in bytes
    
    # Wait for confirmation
    a = bytes.decode(server_main_socket.recv(1))
    return a == "1" # a='1' means signing was correct
            
# Generates and stored the pair of asymmetric keys
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
    with open('crypto/private_key.pem', 'wb') as f:
        f.write(pem)
        
    # Write the public key in public_key.pem
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open('crypto/public_key.pem', 'wb') as f:
        f.write(pem)

# Get the keys that are stored in a file
def get_keys(): # Source of this function : https://nitratine.net/blog/post/asymmetric-encryption-and-decryption-in-python/
    if not os.path.exists("crypto/private_key.pem") or not os.path.exists("crypto/public_key.pem"):
        print("Asymetric keys don't exist yet, creating them...")
        generate_keys() # Generates the public and private keys and store them into files
    
    with open("crypto/private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    
    with open("crypto/public_key.pem", "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
        
    return private_key, public_key

# Gets the leys that are stored in a file in a string format
def read_keys(): # Source of this function : https://nitratine.net/blog/post/asymmetric-encryption-and-decryption-in-python/
    print("Read keys : " + str(os.path.exists("crypto/private_key.pem")))
    if not os.path.exists("crypto/private_key.pem") or not os.path.exists("public_key.pem"):
        print("Asymetric keys don't exist yet, creating them...")
        generate_keys() # Generates the public and private keys and store them into files
    
    key_file = open("crypto/private_key.pem", "r")
    private_key = key_file.read()
    
    key_file = open("crypto/public_key.pem", "r")
    public_key = key_file.read()
        
    return private_key, public_key
    
# Wait for the symmetric key to be sent by the server then decrypts it using the private key
def get_symmetric_key_from_server(server_main_socket, public_key):
    encrypted_symm_key = server_main_socket.recv(1024) # The key can stay in bytes, no need to convert in str
    
    private_key, public_key = get_keys()
    symm_key = private_key.decrypt( # Decryption
        encrypted_symm_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    symm_key = bytes.decode(symm_key) # Turn from bytes to str
    #print("Decrypted symmetric key : " + symm_key)
    return symm_key
    
def create_symmetric_key(user): # Creates a new symmetric key for the conversation with user
    server_listen_socket.send(str.encode("1NEW")) # Send the query to the server
    time.sleep(0.1)
    server_listen_socket.send(str.encode(user))
                
    private_key, public_key = get_keys()
    symm_key = get_symmetric_key_from_server(server_main_socket, public_key) # Wait for the client to generate a symmetric key, encrypt it and send it back to us via the server
    
    if not os.path.exists("crypto/symmetric_keys_" + usr + ".txt"): # If the file doesn't exist yet, create it
        with open("crypto/symmetric_keys_" + usr + ".txt", 'w') as f:
            f.write("")
            
    with open("crypto/symmetric_keys_" + usr + ".txt", "a") as f:
        f.write(user + " " + symm_key + "\n") # Stores the symmetric key
        symm_keys[user] = symm_key


########## GUI ##########


def init_gui(): # Initial screen of the GUI
    global root
    root = tk.Tk()
    root.geometry('600x400')
    root.resizable(False, False)
    root.title('login signup')

    pygame.init()
    pygame.mixer.music.load('audio/login.mp3') # Music
    pygame.mixer.music.play(-1)
    pygame.mixer.music.set_volume(0)

    bg = tk.PhotoImage(file="images/home.png")
    bg = bg.zoom(1)
    bg = bg.subsample(6)
    label1 = tk.Label(root, image=bg)
    label1.place(x=0, y=0)

    # Creating buttons
    buttonlogin = tk.Button(root, text="Login", command=login_gui)
    buttonregister = tk.Button(root, text="Register", command=register_gui)
    buttonmusic = tk.Button(root, text="music", command=mute_unmute)

    buttonlogin.place(x=310, y=280)
    buttonregister.place(x=300, y=200)
    buttonmusic.place(x=110,y=120)
    root.mainloop()
    
def refresh(text, history): # Refresh the GUI
    global usr
    text.configure(state=tk.NORMAL)
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

        text.insert(tk.INSERT, '[from ' + from_username + ' at ' + time + '] ', 'name')
        text.insert(tk.INSERT, decrypted_message + "\n", 'message')
        text.tag_config('name', foreground="green", font=(font, 8))
        text.tag_config('message', foreground="green")

    text.configure(state=tk.DISABLED)
    
def mute_unmute(): # Change the status of the mute of the music
    if pygame.mixer.music.get_volume() > 0:
        pygame.mixer.music.set_volume(0)
    else:
        pygame.mixer.music.set_volume(1)
        
def register_gui(): # Signup screen of the GUI
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

    submit = tk.Button(root, text='Submit', font=(font, 10, 'bold'), width=14, bg='green', command = lambda:signup(ip, resp, user_entry.get(), pass_entry.get()), fg='black')
    submit.place(x=10, y=180)

    tk.Label(root, text='Already Have an account ?', bg='white', font=(font, 10, "normal")).place(x=30, y=210)

    tk.Button(root, text='login', font=(font, 10, 'underline'), bg='white', fg='blue',
              command=login_gui).place(x=200, y=210)

    root.bind('<Return>', init_gui)

    root.mainloop()

def login_gui(): # Login screen of the GUI
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

    submit = tk.Button(root, text='Submit', font=(font, 10, 'bold'), width=14, bg='green', command= lambda: login(ip, resp, user_entry.get(), pass_entry.get()), fg='black')
    submit.place(x=10, y=180)

    tk.Label(root, text='Don\'t Have An Account ?', bg='white', font = (font, 10, "normal")).place(x=30, y=210)

    tk.Button(root, text='Register', font=(font, 10, 'underline'), bg='white', fg='blue', command = register_gui).place(x=200, y=210)

    resp = tk.Label(root, text='', font=('Arial Black', 10, 'bold'), bg='white')
    resp.place(x=10, y=250)

    root.mainloop()

def chat_init_gui(): # Chat window of the GUI
    global root
    global usr
    global user_to

    pygame.mixer.music.stop()
    user_to = ""
    root.destroy()
    root = tk.Tk()
    root.title('Chat')
    root.geometry('600x400')
    root.resizable(False, False)

    # Chat window
    tk.Label(root, text='Chat', bg='white', font=(font, 13), fg='black', width=50, height=1).place(x=-200, y=20)
    text = scrolledtext.ScrolledText(root, height=17, width=41, font=(font, 10), wrap='word')
    text.place(x=10, y=40)
    text.yview(tk.END)
    text.configure(state=tk.NORMAL)
    text.configure(state=tk.DISABLED)

    msg_entry = tk.Entry(root, font=(font, 13), width=25)
    msg_entry.place(x=10, y=365)

    resp = tk.Label(root, text='', font=(font, 10, 'bold'), bg='white')
    resp.place(x=10, y=250)
    
    # Configuration of the send button
    sendbutton = tk.Button(root, font=(font, 10), text='Send', bd=0, bg='blue', fg='black', width=10, command=lambda:send_message(resp, text, msg_entry.get(), msg_entry))
    sendbutton.place(x=300, y=365)

    # Configuration of the disconnect button
    disconnect_button = tk.Button(root, font=(font, 10), text='disconnect', bd=0, bg='blue', fg='red', width=10, command=disconnect)
    disconnect_button.place(x=300, y=330)

    # Choice box containing active users
    sendto_label = tk.Label(root, font=(font, 13), bg='blue', fg='black', text=user_to, width=15)
    sendto_label.place(y=40, x=400)

    tk.Label(root, font=(font, 13), bg='Green', fg='black', text='Users', width=10).place(y=200, x=400)
    active_users = tk.Listbox(root, height=8, width=20)
    active_users.place(x=400, y=230)

    tk.Label(root, text='Logged In as : \n' + usr, font=(font, 10)).place(x=400, y=360)

    active_users = tk.Listbox(root, height=8, width=20)
    active_users.place(x=400, y=230)

    def callback(event): # Called when the user selects another user to talk to
        global user_to
        selection = event.widget.curselection()
        if selection:
            index = selection[0]
            selected = event.widget.get(index) # Gets the selection
            time.sleep(0.1)
            
            if selected not in symm_keys: # If we didn't create a symmetric key with this user yet
                create_symmetric_key(selected)
            
            sendto_label.configure(text=selected)
            user_to = sendto_label.cget("text")
            get_history_from_server(username1=usr, username2=user_to)
        else:
            sendto_label.configure(text="")

    active_users.bind("<<ListboxSelect>>", callback) # Gets the user we clicked on
    user_to = sendto_label.cget("text") # Updates the user we want to talk to

    start_new_thread(receive_messages, (text, active_users))
    root.mainloop()
    
    
######### USER INTERACTIONS ##########


def signup(ip, resp, usr, pswd): # Function called when the user presses the sign up button
    global server_main_socket
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
            
def login(ip, resp, entered_usr, pswd): # Function called when the user presses the login button
    global usr # Must be global fot eh GUI to be able to show it
    global server_main_socket
    global server_listen_socket
    global server_main_socket
    
    usr = entered_usr
    server_main_socket = connect_to_server(ip, 10000)  # The server port number to connect is 10000
    server_main_socket.send(str.encode("0"))  # Code stating we want to login
        
    server_main_socket.send(str.encode(usr))
    salt = bytes.fromhex(bytes.decode(server_main_socket.recv(32)))
    pw_hash = hashlib.pbkdf2_hmac("sha256", str.encode(pswd), salt, 100000) # 100 000 is the number of iterations of sha-256
    server_main_socket.send(str.encode(pw_hash.hex()))  # str.encode() to transform the string into bytes

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
                #start_new_thread(listen_for_messages, ())
            chat_init_gui()
    else:
        raise Exception("Unexpected answer")
        
        
def receive_messages(text, active_users):  # Listen from messages from the server and displays them
    global user_to
    while True:
        sender = bytes.decode(server_main_socket.recv(10))
        if disconnection: # If the user wants to be disconnected we stop receiving data for this user
            print("Disconnection")
            return

        if sender == "1NEW": # Create a new contact
            #server_main_socket.send(str.encode("1")) # Confirmation
            sender = bytes.decode(server_main_socket.recv(10))
            public_key = bytes.decode(server_main_socket.recv(1024))
            encrypted_symm_key = generate_symmetric_key(usr, sender, public_key)
            print(encrypted_symm_key)
            server_main_socket.send(encrypted_symm_key)
        elif sender == "2HISTORY" :
            print("Received history from server : ")
            history = bytes.decode(server_main_socket.recv(2048))
                
            # Translates "history" string into a list, and the stringified tuples into tuples
            history_cleaned = ast.literal_eval(history)
            refresh(text, history_cleaned)

        elif sender == "3UPDATE" :
            print("There is an update in the list of the logged-in users : ", end='')
            logged_in_users = bytes.decode(server_main_socket.recv(2048))
            logged_in_users_list = ast.literal_eval(logged_in_users)

            print(logged_in_users_list)

            refresh_active_users(active_users, logged_in_users_list)
            if user_to not in logged_in_users_list: # If the user selected is not active anymore
                user_to = "" # Deselect it to avoid sending messages to inactive users

        else :
            data = server_main_socket.recv(2048)
            f = Fernet(symm_keys[sender])
            print("Message to decrypt : ", end='')
            print(data)
            decrypted_message = bytes.decode(f.decrypt(data))
            print("Message decrypted : " + decrypted_message)

            text.configure(state=tk.NORMAL)
            # Get current time
            now = datetime.now()
            curr_time = now.strftime("%d-%m-%Y %H:%M:%S")
                
            text.insert(tk.INSERT, '[from ' + sender + ' at ' + curr_time + '] ', 'name')
            text.insert(tk.INSERT, decrypted_message + "\n", 'message')
            text.tag_config('name', foreground="green", font=(font, 8))
            text.tag_config('message', foreground="green")
            text.configure(state=tk.DISABLED)

            receive_sound = pygame.mixer.Sound("audio/receive.wav")
            pygame.mixer.Sound.play(receive_sound)
            
def send_message(resp, text, data, msg_entry):   # Function called when the user presses the send button
    if data == "":
        resp.configure(text="Attempt to send an empty message", fg='red')
    elif user_to == "":
        resp.configure(text="Please select a receiver for this message", fg='red')
    else:
        resp.configure(text="", fg='red') # Erase previous error messages
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
        now = datetime.now() # Get current time
        curr_time = now.strftime("%d-%m-%Y %H:%M:%S")
        text.insert(tk.INSERT, '[from ' + usr + ' at ' + curr_time + ']', 'name')
        text.insert(tk.INSERT, data + "\n", 'message')
        text.tag_config('name', foreground="green", font=(font, 8))
        text.tag_config('message', foreground="green")
        text.configure(state=tk.DISABLED)

        print("message envoyé")
        msg_entry.delete(0, 'end')


########## STARTING ##########

init_gui() # Starts the GUI
