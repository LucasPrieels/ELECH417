#!/usr/bin/python3

import socket, random, secrets, hmac, time
from _thread import *
from connect import connect, disconnect
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature
from db_queries_inserts import *

clients = {} # List of clients connected with their username and their socket
current_port = 0 # Number of the last port asigned to a client


########## SOCKETS ##########


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
    
    
########### SECURITY ##########


def transform_string_to_key(public_key_string):
    # Transforms the string version of the public key (used to be stored) into a real cryptography public key
    public_key_full = "-----BEGIN PUBLIC KEY-----\n" + public_key_string + "\n-----END PUBLIC KEY-----\n"
    public_key = serialization.load_pem_public_key(
        str.encode(public_key_full),
        backend=default_backend()
    )
    return public_key
    

########## MAIN FUNCTIONS ##########

def signup(main_connection):
    # Get the list of all users from DB
    existing_users = db_get_users(db_connection)

    # Gets from client the following parameters for a registration
    usr, pswd, salt, public_key_string = bytes.decode(client_connection.recv(2048)).split(' ')

    if usr in existing_users: # If user already exists
        main_connection.send(str.encode("0"))
        print("Signup unsuccessful")
        return -1
    else:
        # We can register

        # First, insert new created profile in DB
        db_insert_new_user(db_connection, usr, pswd, salt, public_key_string)
        # Then, send back confirmation message to the client
        main_connection.send(str.encode("1"))

        print("Signup successful")
        return usr

def login(main_connection):
    global clients 
    existing_users = db_get_users(db_connection)
    
    # Receive attempted username from client
    usr = bytes.decode(client_connection.recv(1024))

    # Send to client the salt of this client, that is stored in DB
    client_connection.send(str.encode(str(db_get_salt_from_username(db_connection, usr))))
    
    # Get the password attempt from client
    pswd_hashed = bytes.decode(client_connection.recv(1024))
    
    if usr not in existing_users: # If the username is not correct
        client_connection.send(str.encode("0"))
        print("Login unsucessful")
        return -1, -1

    if db_get_password_from_username(db_connection, usr) != pswd_hashed: # If the password is not correct
        main_connection.send(str.encode("1"))
        print("Login unsucessful")
        return -1, -1
    else:
        # Login successful
        # Update last login time
        db_update_last_login(db_connection, usr)

        # Send to client the information that login is successful
        main_connection.send(str.encode("2"))
        
        nonce = secrets.token_urlsafe(32) # Generates a random nonce
        main_connection.send(str.encode(nonce)) # And sends it to the client
        
        # Receives encrypted signature from client
        encrypted_private_key_nonce = client_connection.recv(1024)
        
        # Get public key from DB
        public_key = transform_string_to_key(db_get_publickey_from_username(db_connection, usr))
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

# Listen to messages arriving from a client and displays them in real time
def server_listener(usr):
    client_connection, client_listen_connection = clients[usr] # Gets the sending and listening connections for this user

    while True:
        recipient = bytes.decode(client_listen_connection.recv(10))
        # The recipient can either be the name of an active user, or a code to transmit information to the server
        
        # Code for the client when it is disconnected (removing from list of active users)
        if recipient == "0DISCONNEC":
            print("User " + usr + " disconnected")
            clients.pop(usr) # Remove the client from the list of active users

            # Send to all clients the updated list of connected clients
            for username, values in clients.items():
                usernames_copy = list(clients.keys()).copy()
                usernames_copy.remove(username)

                client_connection = values[0]

                time.sleep(0.2) # Sleeps to avoid colliding the packets while they are sent
                # Informs the client socket that an update is coming
                client_connection.send(str.encode("3UPDATE"))
                time.sleep(1)
                # Send to each user a list of all logged-in users BUT the concerned user itself
                client_connection.send(str.encode(str(usernames_copy)))
                time.sleep(0.2)

            break # Stop listening to this client
        elif recipient == "1NEW": # Code for a client to open a conversation with another activer user
            recipient = bytes.decode(client_listen_connection.recv(10)) # Get the username of the new contact
            recipient_connection, recipient_listen_connection = clients[recipient] # Retrieve the socket of the recipient
            recipient_connection.send(str.encode("1NEW")) # Forward the code to the recipient
            time.sleep(0.1)
            recipient_connection.send(str.encode(usr)) # Sending the name of the sender to the recipient
            time.sleep(0.1)
            recipient_connection.send(str.encode(db_get_publickey_from_username(db_connection, usr))) # Sending the public key of the sender to the recipient
            encrypted_symm_key = recipient_connection.recv(1024) # Waiting for the encrypted symmetric key created by the recipient
            client_connection.send(encrypted_symm_key) # Retransmit the reply of the recipient to the client
        
        elif recipient == "2HISTORY" : # Code to ask history of messages in a conversation from the server
            # Collect the usernames of people participating in the conversation from the client
            username1 = bytes.decode(client_listen_connection.recv(64))
            username2 = bytes.decode(client_listen_connection.recv(64)) 

            id1, id2 = db_get_id_from_username(db_connection, username1), db_get_id_from_username(db_connection, username2)

            history = db_get_messages_from_two_ids(db_connection, id1, id2)

            time.sleep(0.1)
            client_connection.send(str.encode("2HISTORY"))
            time.sleep(0.1)
            client_connection.send(str.encode(str(history))) # Send the history back to the sender

        elif recipient not in clients:
            client_listen_connection.send(str.encode("0")) # The user which need to be contacted doesn't exist or is not connected
        else:
            # The client is a user, we want to send him an encrypted message
            client_listen_connection.send(str.encode("1"))
            recipient_connection, recipient_listen_connection = clients[recipient]
            recipient_connection.send(str.encode(usr))
            print("Forwarding a message from user " + usr + " to " + recipient, end='')
            
            data = bytes.decode(client_listen_connection.recv(2048)) # Gets the content of the message

            # Insert message in DB
            db_insert_new_message(db_connection, usr, recipient, data)
            print(data)
            recipient_connection.send(str.encode(data))



########## SERVER INITIALIZATION ##########


main_socket = create_new_socket(10000) # Main socket, used by the server to send data and to listen to new connections. Port number is 10 000 by definition
db_connection = connect() # Connection to the database

while True:
    client_connection, address = main_socket.accept() # Wait for connection on this socket
    print("Connection from address " + str(address))
    
    query = bytes.decode(client_connection.recv(1)) # Waiting for query
    if query == "0": # Code for a login
        usr, socket_client = login(client_connection)
        if usr == -1:
            continue # Login unsucessful
        else:
            # Login successful
            client_listen_connection, address = socket_client.accept()
            clients[usr] = (client_connection, client_listen_connection) # Add the user to the list of connected users
            
            # Send to all clients the list of connected clients
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

            start_new_thread(server_listener, (usr,)) # Start the listener on a thread
    elif query == "1":
        usr = signup(client_connection)
    elif query == "":
        continue # Connection closed by the client
    elif query == "6" :
        disconnect(db_connection)
    else:
        print(query)
        raise Exception("Unexpected query")

disconnect(db_connection)
