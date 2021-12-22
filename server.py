#!/usr/bin/python3

import socket, random, secrets, hmac, time
from _thread import *
from connect import connect, disconnect
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature


clients = {} # List of clients connected with their username and their socket
current_port = 0

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
    
    socket = create_new_socket(current_port)
    client_connection.send(str.encode(str(current_port))) # Send the port number to the client
    return socket


def get_users_from_db() :
    """
    Returns a list of all users in DB
    """
    global db_connection
    cur = db_connection.cursor()
    cur.execute("SELECT username FROM users ;")
    cred = []
    for user in cur.fetchall() :
        cred.append(user[0])
    cur.close()
    return cred

def signup(main_connection):
    global db_connection
    
    # Whatever the credentials are (valid or not), we create a cursor to query the DB
    cur = db_connection.cursor()
    
    existing_users = get_users_from_db()

    # Gets from client the following parameters for a registration
    usr, pswd, salt, public_key_string = bytes.decode(client_connection.recv(2048)).split(' ')

    print(pswd)
    print("Public key of user : " + public_key_string)

    if usr in existing_users: # User already exists
        cur.close() 
        main_connection.send(str.encode("0"))
        print("Signup unsuccessful")
        return -1
    else:
        # We can register

        # First, insert new created profile in DB
        insertion_query = """
        INSERT INTO users(username, password, salt, created_on, last_login, client_public_key)
        VALUES ('{}','{}', '{}', now(), now(), '{}');
        """.format(usr, pswd, salt, public_key_string)
        cur.execute(insertion_query)

        # Commit change to DB 
        db_connection.commit() 
        print("Added user to DB ")
        cur.close()
        
        
        # Then, send back message
        main_connection.send(str.encode("1"))

        print("Signup successful")
        return usr


def authentication(username, pw_hash) :
    """
    Gets the password from the DB and verifies it matches the entry
    Here we assume username is in the DB, as it has been verified in a previous function.
    """
    global db_connection

    # Execute query on DB
    cur = db_connection.cursor()
    query = """
    SELECT password FROM users WHERE username = '{}'
    """.format(username)
    cur.execute(query)
    res = cur.fetchone()
    
    # Get hashed password
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
    
def transform_string_to_key(public_key_string):
    # Transforms the string version of the public key into a real cryptography public key
    public_key_full = "-----BEGIN PUBLIC KEY-----\n" + public_key_string + "\n-----END PUBLIC KEY-----\n"
    public_key = serialization.load_pem_public_key(
        str.encode(public_key_full),
        backend=default_backend()
    )
    return public_key
    
def get_client_public_key(username):
    global db_connection
    cur = db_connection.cursor()
    query = """
    SELECT client_public_key FROM users WHERE username = '{}'
    """.format(username)
    cur.execute(query)

    res = cur.fetchone()[0]
    print("The public key of user " + username + " is " + res)
    return res
    
def get_salt_from_db(username):
    global db_connection
    cur = db_connection.cursor()
    query = """
    SELECT salt FROM users WHERE username = '{}'
    """.format(username)
    cur.execute(query)

    try:
        res = cur.fetchone()[0]
        print("The salt of user " + username + " is " + res)
        return res
    except:
        return (str.encode("a")).hex()

def login(main_connection):
    global clients 
    existing_users = get_users_from_db()
    
    # Receive attempt username from client
    usr = bytes.decode(client_connection.recv(1024))

    # Send to client the salt of this client, that is stored in DB
    client_connection.send(str.encode(str(get_salt_from_db(usr))))
    
    # Get the password attempt from client
    pswd_hashed = bytes.decode(client_connection.recv(1024))
    
    if usr not in existing_users:
        client_connection.send(str.encode("0"))
        print("Login unsucessful")
        return -1, -1

    pw_check = authentication(usr, pswd_hashed)
    if not pw_check:
        main_connection.send(str.encode("1"))
        print("Login unsucessful")
        return -1, -1
    else:
        
        # Login successful
        update_last_login(usr)

        # Send to client the information that login is successful
        main_connection.send(str.encode("2"))

        
        nonce = secrets.token_urlsafe(32) # Generates a random nonce
        main_connection.send(str.encode(nonce)) # And sends it to the client
        
        # Receives encrypted signature from client
        encrypted_private_key_nonce = client_connection.recv(1024)
        
        public_key = transform_string_to_key(get_client_public_key(usr))
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
        

def get_id_from_username(username):
    global db_connection
    cur = db_connection.cursor()

    cur.execute("""
    SELECT user_id FROM users WHERE username='{}'
    """.format(username))
    return cur.fetchone()[0]

def display_history_of(id1, id2) :
    global db_connection
    cur = db_connection.cursor()
    query = """
    SELECT u1.username as from , u2.username as to, m.content, to_char(m.time, 'MM-DD-YYYY HH24:MI:SS')
    FROM messages m, users u1 , users u2
    WHERE ((m.from_id = {} AND m.to_id = {})
        OR (m.from_id = {} AND m.to_id = {}))
        AND (m.from_id = u1.user_id AND m.to_id = u2.user_id)
    ORDER BY time
    /* LIMIT 5*/ 
        ;
    """.format(id1, id2, id2, id1)


    cur.execute(query)
    results = cur.fetchall()
    cur.close()
    
    return results

def server_listener(usr): # Listen to messages arriving from a client and displays them

    client_connection, client_listen_connection = clients[usr] # Gets the sending and listening connections for this user
    
    while True:
        recipient = bytes.decode(client_listen_connection.recv(10))
        print("Message for : " + recipient)
        
        if recipient == "" or recipient == ".": # Code for the client to be disconnected
            print("User " + usr + " disconnected")
            clients.pop(usr) # Remove the client from the list of active users
            break # Stop listening to this client

        elif recipient == "1NEW": # Code to connect to a new contact
            #client_listen_connection.send(str.encode("1"))
            recipient = bytes.decode(client_listen_connection.recv(10))
            recipient_connection, recipient_listen_connection = clients[recipient]
            print("Sending code 1NEW to recpient " + recipient)
            recipient_connection.send(str.encode("1NEW"))
            time.sleep(0.1)
            print("Sending the sender of the query : " + usr)
            recipient_connection.send(str.encode(usr))
            time.sleep(0.1)
            print("Sending public key of user " + usr)
            recipient_connection.send(str.encode(get_client_public_key(usr)))
            encrypted_symm_key = recipient_connection.recv(1024)
            print("Received encrypted symmetric key : ", end='')
            print(encrypted_symm_key)
            print("Forwarding the symmetric key to " + usr)
            client_connection.send(encrypted_symm_key) # Retransmit the reply of the recipient to the client (the encrypted symmetric key or an error message)
        
        elif recipient == "2HISTORY" : # Code to ask history from server
            print("Server has been asked to show history")
            # Collect usernames from the client
            username1 = bytes.decode(client_listen_connection.recv(64))
            username2 = bytes.decode(client_listen_connection.recv(64)) 

            id1, id2 = get_id_from_username(username1), get_id_from_username(username2)

            history = display_history_of(id1, id2)

            time.sleep(0.1)
            client_connection.send(str.encode("2HISTORY"))
            time.sleep(0.1)
            client_connection.send(str.encode(str(history)))

        elif recipient not in clients:
            client_listen_connection.send(str.encode("0")) # The user which need to be contacted doesn't exist or is not connected
        else:
            # The client is a user and wants to send a message
            client_listen_connection.send(str.encode("1"))
            recipient_connection, recipient_listen_connection = clients[recipient]
            recipient_connection.send(str.encode(usr))
            print("Forwarding a message from user " + usr + " to " + recipient + " : ", end='')
            
            data = bytes.decode(client_listen_connection.recv(2048))

            # Insert message in DB
            cur = db_connection.cursor()
            cur.execute("""
            INSERT INTO messages(from_id, to_id, content, time)
            VALUES({}, {}, '{}', NOW())
            """.format(get_id_from_username(usr), get_id_from_username(recipient), data))
            cur.close()
            db_connection.commit()

            print(data)
            recipient_connection.send(str.encode(data))



####################

# Server initialization


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
            # Login successful
            client_listen_connection, address = socket_client.accept() # From now on, listen on connection client_listen_connection and send on client_connection. Address is the same as before since it's the same client
            clients[usr] = (client_connection, client_listen_connection) # Add the user to the list of connected users
            print(clients)
            # Send to all clients the list of connected clients

            # Get list of all usernames : clients.keys()

            for username, values in clients.items() :
                usernames_copy = list(clients.keys()).copy()
                usernames_copy.remove(username)

                client_connection = values[0]
                client_listen_connection = values[1]
                
                time.sleep(0.2)
                # Informs the client socket that an update is coming
                client_connection.send(str.encode("3UPDATE"))
                time.sleep(1)
                # Send to each user a list of all logged-in users BUT the concerned user itself
                client_connection.send(str.encode(str(usernames_copy)))
                time.sleep(0.2)

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
