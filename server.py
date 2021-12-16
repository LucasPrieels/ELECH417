import socket

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
    s.listen(5) # Max number of clients that can be connected at the same time to this socket
    
    return s
    
def login(credentials):
    received = bytes.decode(conn.recv(1024)).split(' ')
    usr = received[0]
    pswd = received[1]
    if usr not in credentials:
        conn.send(str.encode("0"))
        return -1
    elif credentials[usr] != pswd:
        conn.send(str.encode("1"))
        return -1
    else:
        conn.send(str.encode("2"))
        return usr
        
    return usr;

credentials = parse_credentials_file()

listen_socket = create_listen_socket(9999) # Port number

while True:
    conn,addr = listen_socket.accept() # Wait for connection on this socket
    print ("Connection from address " + str(addr))
    try:
        usr = login(credentials)
        if usr == -1:
            print("Login unsucessful")
        else:
            print("Login successful")
    finally:
        conn.close()
        print("Connection closed")
