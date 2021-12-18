#!/usr/bin/python3

import socket, time

def connect_to_server(ip, remote_port):
    s = socket.socket()    # Remote socket
    host = socket.gethostname() # Remote address (here same as local since local tests)
    if ip == "-1": # If local
        ip = host
    print("Remote port : " + str(remote_port))
    s.connect((ip, remote_port))
    return s

def login(ip):
    print("####### LOGIN #######")
    usr = input("Username : ")
    pswd = input("Password : ")
    server_main_socket = connect_to_server(ip, 10000) # The server port number to connect is 10000

    server_main_socket.send(str.encode("0")) # Code stating we want to login
    server_main_socket.send(str.encode(str(usr) + " " + str(pswd))) # str.encode() to transform the string into bytes
    
    ans = bytes.decode(server_main_socket.recv(1)) # 1 byte is enough
    if ans == "0":
        print("Username unkown\n")
        return -1, -1, -1
    elif ans == "1":
        print("Password incorrect\n")
        return -1, -1, -1
    elif ans == "2":
        print("Connection successful\n")
        remote_port = bytes.decode(server_main_socket.recv(4)) # 4 bytes for a port number between 2000 and 3000 (in string format so each character takes a byte)
        listen_socket = connect_to_server(ip, int(remote_port)) # Connect to the new port specific for this client, given by the server
        return usr, server_main_socket, listen_socket
    else:
        raise Exception("Unexpected answer")
        
def signup(ip):
    print("####### SIGNUP #######")
    usr = input("Username : ")
    pswd = input("Password : ")
    server_main_socket = connect_to_server(ip, 10000) # The server port number to connect is 10000
    
    server_main_socket.send(str.encode("1")) # Code stating we want to sign up
    server_main_socket.send(str.encode(str(usr) + " " + str(pswd))) # str.encode() to transform the string into bytes
    
    ans = bytes.decode(server_main_socket.recv(1)) # 1 byte is enough, it's the status of the query
    if ans == "0":
        print("Username already used\n")
        return -1
    elif ans == "1":
        print("Signup successful\n")
        return usr
    else:
        raise Exception("Unexpected answer")

#try:
ip = "-1"# 192.168.1.30" # IP address of the remote server, or -1 for local
while True:
    log = input("Do you want to sign up (0) or login (1)?")
    if log == "0":
        signup(ip)
    elif log == "1":
        usr, server_main_socket, listen_socket = login(ip)
        if usr != -1:
            print("You can now send messages, hit return to send them and send '.' to stop")
            while True:
                data = input()
                server_main_socket.send(str.encode(data))
                if data == ".": # Stop communication
                    break
    elif log == "666" :
        server_main_socket = connect_to_server(ip, 10000) # The server port number to connect is 10000
        
        server_main_socket.send(str.encode(log))

#finally:
    #server_main_socket.close()
