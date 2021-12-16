import socket

clients = {} # List of clients connected with their username and their socket

def parse_credentials_file():
    credentials = {}
    f = open("credentials.txt", "r")
    for line in f:
        usr, pswd = (line.strip()).split(' ')
        credentials[usr] = pswd
    print(credentials)
    return credentials

def create_listen_socket(port):
    s = socket.socket() # Create a socket object
    host = socket.gethostname() # Current machine name

    s.bind((host,port)) # Bind with the address

    print("Socket created on host " + host + ":" + str(port))
    s.listen(5) # Max number of clients queued
    
    return s
    
def signup():
    credentials = parse_credentials_file()

    received = bytes.decode(conn.recv(1024)).split(' ')
    usr = received[0]
    pswd = received[1]
    if usr in credentials: # User already exists
        conn.send(str.encode("0"))
        print("Signup unsuccessful")
        return -1
    else:
        conn.send(str.encode("1"))
        print("Signup successful")
        f = open("credentials.txt", "a")
        f.write(usr + " " + pswd + "\n")
        return usr
    
def login():
    credentials = parse_credentials_file()
    
    received = bytes.decode(conn.recv(1024)).split(' ')
    usr = received[0]
    pswd = received[1]
    if usr not in credentials:
        conn.send(str.encode("0"))
        print("Login unsucessful")
        return -1
    elif credentials[usr] != pswd:
        conn.send(str.encode("1"))
        print("Login unsucessful")
        return -1
    else:
        conn.send(str.encode("2"))
        print("Login successful")
        return usr

listen_socket = create_listen_socket(9999) # Port number

while True:
    conn,addr = listen_socket.accept() # Wait for connection on this socket
    print ("Connection from address " + str(addr))
    try:
        query = bytes.decode(conn.recv(1)) # Waiting for query
        print(query)
        if query == "0":
            usr = login()
        elif query == "1":
            usr = signup()
        elif query == "":
            continue # Connection closed by the client
        else:
            raise Exception("Unexpected query")
    finally:
        conn.close()
        print("Connection closed")
