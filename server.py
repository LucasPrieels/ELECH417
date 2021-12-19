#!/usr/bin/python3

import socket, random
from _thread import *
from connect import connect, disconnect
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
    
def new_socket_client(main_connection): # Associate a new port number and socket to each new client
    global current_port
    if current_port == 0: # If the current port is not initialized, we give it a random value between 2000 and 3000
        current_port = random.randrange(2000, 3000)
    else:
        current_port += 1 # To give a different port number to each client
    #print("Port : " + str(current_port))
    
    socket = create_new_socket(current_port)
    main_connection.send(str.encode(str(current_port))) # Send the port number to the client
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


def signup(main_connection):
    global db_connection
    
    # Whatever the credentials are (valid or not), we create a cursor to query the DB
    cur = db_connection.cursor()

    # credentials = parse_credentials_file()
    # New version, using DB
    credentials = get_users_from_db()

    received = bytes.decode(main_connection.recv(1024)).split(' ')
    usr = received[0]
    pswd = received[1]
    if usr in credentials: # User already exists
        cur.close() 
        main_connection.send(str.encode("0"))
        print("Signup unsuccessful")
        return -1
    else:
        # First, insert new created profile in DB
        cur.execute("""
        INSERT INTO users(username, password, created_on, last_login) 
        VALUES ('{}','{}', now(), now());
        """.format(usr, pswd))

        # Commit change to DB 
        db_connection.commit() 
        print("Normalement dans la DB ")
        cur.close()
        f = open("credentials.txt", "a")
        f.write(usr + " " + pswd + "\n")
        
        # Then, send back message
        main_connection.send(str.encode("1"))
        print("Signup successful")
        return usr


def authentication(username, password) :
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

    res = cur.fetchone()[0]
    print(password, res)
    return password == res

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

def login(main_connection):
    credentials = get_users_from_db()
    
    received = bytes.decode(main_connection.recv(1024)).split(' ')
    usr = received[0]
    pswd = received[1]
    
    if usr not in credentials:
        main_connection.send(str.encode("0"))
        print("Login unsucessful")
        return -1, -1

    pw_check = authentication(usr, pswd)    
    if not pw_check:
        main_connection.send(str.encode("1"))
        print("Login unsucessful")
        return -1, -1
    else:
        update_last_login(usr)

        main_connection.send(str.encode("2"))
        print("Login successful")
        return usr, new_socket_client(main_connection)
        
def server_listener(main_connection, usr): # Listen to messages arriving from a client and displays them
    while True: # Receive data while there is some left
        data = bytes.decode(main_connection.recv(2048))
        if data == "" or data == ".": # Stop communication
            print("User " + usr + " disconnected")
            break
        print("From user " + usr + " : " + data)

main_socket = create_new_socket(10000) # Main socket, used by the server to send data and to listen to new connections. Port number is 10 000 by definition
db_connection = connect()

query = ""
while True :
    main_connection,address = main_socket.accept() # Wait for connection on this socket
    print("Connection from address " + str(address))
    #try:
    query = bytes.decode(main_connection.recv(1)) # Waiting for query
    if query == "0":
        usr, socket_client = login(main_connection)
        if usr == -1:
            continue # Login unsucessful
        else:
            start_new_thread(server_listener, (main_connection, usr))
    elif query == "1":
        usr = signup(main_connection)
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