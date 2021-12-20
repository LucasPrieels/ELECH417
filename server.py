#!/usr/bin/python3

import socket, random, secrets, hmac
from _thread import *
from connect import connect, disconnect
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature

clients = {} # List of clients connected with their username and their socket
current_port = 0

def parse_credentials_file(): # Read the credentials file to get the users and passwords
    credentials = {}
    f = open("credentials.txt", "r")
    for line in f:
        usr, pswd = (line.strip()).split(' ')
        credentials[usr] = pswd
    #print(credentials)
    return credentials

def create_new_socket(port):
    s = socket.socket() # Create a socket object
    host = socket.gethostname() # Current machine name

    s.bind((host,port)) # Bind with the address

    print("Socket created on host " + host + ":" + str(port))
    s.listen(5) # Max number of clients queued
    
    return s
    
def new_socket_client(client_connection): # Associate a new port number and socket to each new client
    global current_port
    if current_port == 0: # If the current port is not initialized, we give it a random value between 2000 and 3000
        current_port = random.randrange(2000, 3000)
    else:
        current_port += 1 # To give a different port number to each client
    #print("Port : " + str(current_port))
    
    socket = create_new_socket(current_port)
    client_connection.send(str.encode(str(current_port))) # Send the port number to the client
    return socket

def get_users_from_db() :
    global db_connection
    cur = db_connection.cursor()
    cur.execute("SELECT username FROM users ;")
    cred = []
    for user in cur.fetchall() :
        cred.append(user[0])
    cur.close()
    return cred

def transform_string_to_key(public_key_string):
    # Transforms the string version of the public key into a real cryptography public key
    public_key_full = "-----BEGIN PUBLIC KEY-----\n" + public_key_string + "\n-----END PUBLIC KEY-----\n"
    public_key = serialization.load_pem_public_key(
        str.encode(public_key_full),
        backend=default_backend()
    )
    return public_key

def signup(main_connection):
    global db_connection
    
    # Whatever the credentials are (valid or not), we create a cursor to query the DB
    cur = db_connection.cursor()

    # credentials = parse_credentials_file()
    # New version, using DB
    credentials = get_users_from_db()

    usr, pswd, salt, public_key_string = bytes.decode(client_connection.recv(2048)).split(' ')
    print(pswd)
    print("Public key of user : " + public_key_string)
    
    # Generates the symmetric key for the connection with this user
    symm_key = Fernet.generate_key()
    print("Symmetric key for this connection : " + bytes.decode(symm_key))

    if usr in credentials: # User already exists
        cur.close() 
        main_connection.send(str.encode("0"))
        print("Signup unsuccessful")
        return -1
    else:
        # First, insert new created profile in DB
        cur.execute("""
        INSERT INTO users(username, password, salt, created_on, last_login, client_public_key, symmetric_key)
        VALUES ('{}','{}', '{}', now(), now(), '{}', '{}');
        """.format(usr, pswd, salt, public_key_string, bytes.decode(symm_key)))

        # Commit change to DB 
        db_connection.commit() 
        print("User ajouté dans la DB ")
        cur.close()
        #f = open("credentials.txt", "a")
        #f.write(usr + " " + pswd + "\n")
        
        # Then, send back message
        main_connection.send(str.encode("1"))
        
        public_key = transform_string_to_key(public_key_string)
        encrypted_symm_key = public_key.encrypt(
            symm_key, # The message to be encrypted is the symmetric key
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        main_connection.send(encrypted_symm_key) # The encrypted key is already in bytes, no need to convert

        print("Signup successful")
        return usr


def authentication(username, pw_hash) :
    """
    Gets the password from the DB and verifies it matches the entry
    """
    ## Here we assume username is in the DB
    global db_connection
    cur = db_connection.cursor()
    query = """
    SELECT password FROM users WHERE username = '{}'
    """.format(username)
    cur.execute(query)
    res = cur.fetchone()
    pw_hash_db = res[0]
    
    print(username, pw_hash, pw_hash_db)
    return pw_hash == pw_hash_db

def update_last_login(username) :
    # Updates the "last_login" timestamp attribute of the username in the DB
    global db_connection
    cur = db_connection.cursor()
    query = """
    UPDATE users
    SET last_login = now()
    WHERE username = '{}'
    """.format(username)
    cur.execute(query)

    # A modification has been done : commit 
    db_connection.commit()
    return
    
def get_client_public_key(username):
    global db_connection
    cur = db_connection.cursor()
    query = """
    SELECT client_public_key FROM users WHERE username = '{}'
    """.format(username)
    cur.execute(query)

    res = cur.fetchone()[0]
    print("The public key of user " + username + " is " + res)
    return transform_string_to_key(res)
    
def get_salt_from_db(username):
    global db_connection
    cur = db_connection.cursor()
    query = """
    SELECT salt FROM users WHERE username = '{}'
    """.format(username)
    cur.execute(query)

    res = cur.fetchone()[0]
    print("The salt of user " + username + " is " + res)
    return res

def login(main_connection):
    credentials = get_users_from_db()
    
    usr = bytes.decode(client_connection.recv(1024))
    client_connection.send(str.encode(get_salt_from_db(usr)))
    
    pswd_hashed = bytes.decode(client_connection.recv(1024))
    
    if usr not in credentials:
        client_connection.send(str.encode("0"))
        print("Login unsucessful")
        return -1, -1

    pw_check = authentication(usr, pswd_hashed)
    if not pw_check:
        main_connection.send(str.encode("1"))
        print("Login unsucessful")
        return -1, -1
    else:
        update_last_login(usr)

        main_connection.send(str.encode("2"))
        
        nonce = secrets.token_urlsafe(32) # Generates a random nonce
        print("Nonce : ", end='')
        print(nonce)
        main_connection.send(str.encode(nonce)) # And sends it to the client
        
        encrypted_private_key_nonce = client_connection.recv(1024)
        print("Encrypted private key nonce : ", end='')
        print(encrypted_private_key_nonce)
        
        public_key = get_client_public_key(usr)
        try: # Checks encrypted_private_key_nonce is the signature of message nonce. If not, raises an invalid signature exception
            public_key.verify( # See doc on https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
                encrypted_private_key_nonce,
                str.encode(nonce),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        except InvalidSignature:
            main_connection.send(str.encode("0"))
            print("Wrong client private key")
            return -1, -1
        else:
            main_connection.send(str.encode("1"))
            print("Login successful")
            return usr, new_socket_client(client_connection)
        
def server_listener(usr): # Listen to messages arriving from a client and displays them
    client_connection, client_listen_connection = clients[usr] # Gets the sending and listening connections for this user
    while True:
        recipient = bytes.decode(client_listen_connection.recv(10))
        print(recipient)
        if recipient == "" or recipient == ".": # Code for the client to be disconnected
            print("User " + usr + " disconnected")
            clients.pop(usr) # Remove the client from the list of active users
            break # Stop listening to this client
        elif recipient not in clients:
            client_listen_connection.send(str.encode("0")) # The user which need to be contacted doesn't exist or is not connected
        else:
            client_listen_connection.send(str.encode("1"))
            recipient_connection, recipient_listen_connection = clients[recipient]
            recipient_connection.send(str.encode(usr))
            while True:
                data = bytes.decode(client_listen_connection.recv(2048))
                print("From user " + usr + " : " + data)
                if data == "" or data == ".": # Stop communication with this recipient
                    print("Change of conversation")
                    break
                recipient_connection.send(str.encode(data))

main_socket = create_new_socket(10000) # Main socket, used by the server to send data and to listen to new connections. Port number is 10 000 by definition
db_connection = connect()

while True:
    client_connection, address = main_socket.accept() # Wait for connection on this socket
    print("Connection from address " + str(address))
    #try:
    query = bytes.decode(client_connection.recv(1)) # Waiting for query
    if query == "0":
        usr, socket_client = login(client_connection)
        if usr == -1:
            continue # Login unsucessful
        else:
            client_listen_connection, address = socket_client.accept() # From now on, listen on connection client_listen_connection and send on client_connection. Address is the same as before since it's the same cliet
            clients[usr] = (client_connection, client_listen_connection) # Add the user to the list of connected users
            print(clients)
            start_new_thread(server_listener, (usr,))
    elif query == "1":
        usr = signup(client_connection)
    elif query == "":
        continue # Connection closed by the client
    elif query == "6" :
        disconnect(db_connection)
    else:
        print(query)
        raise Exception("Unexpected query")
    #finally:
        #conn.close()
        #print("Connection closed")

disconnect(db_connection)
