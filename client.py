#!/usr/bin/python3

import socket, time
from _thread import *

disconnection = False # It is put to True when the user wants to be disconnected

def connect_to_server(ip, remote_port):
    s = socket.socket() # Remote socket
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
    server_main_socket = connect_to_server(ip, 10001) # The server port number to connect is 10001

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
        server_listen_socket = connect_to_server(ip, int(remote_port)) # Connect to the new port specific for this client, given by the server
        return usr, server_main_socket, server_listen_socket
    else:
        raise Exception("Unexpected answer")
        
def check_credentials(usr, pswd):
    if (usr[0]).isdigit() or len(usr) > 10: # A username can't start with a digit or be longer than 10 characters
        return False
    return True
        
def signup(ip):
    valid_credentials = False
    while not valid_credentials: # While the credentials are not valid we ask for them again
        print("####### SIGNUP #######")
        usr = input("Username : ")
        pswd = input("Password : ")
        valid_credentials = check_credentials(usr, pswd)
        
    server_main_socket = connect_to_server(ip, 10001) # The server port number to connect is 10001
    
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

def listen_for_input(): # Listen for the client's input and sends it to the server
    global disconnection
    while True:
        usr = input("To which user would you like to send messages ? Send '.' to disconnect\n")
        server_listen_socket.send(str.encode(usr)) # Send to the server socket that is listening to us
        reply = bytes.decode(server_listen_socket.recv(1)) # Receive from the main server socket
        
        if usr == ".": # User wants to disconnect
            disconnection = True
            break
        
        if reply == "0":
            print("The specified user doesn't exist or is not connected")
            continue
        
        print("You can now send messages to " + usr + ", hit return to send them and send '.' to stop")
        while True:
            data = input()
            server_listen_socket.send(str.encode(data)) # Send message
            if data == ".": # Stop communication with this user
                break
            
def listen_for_messages(): # Listen from messages from the server and displays them
    sender = bytes.decode(server_main_socket.recv(10))
    while True:
        if disconnection: # If the user wants to be disconnected we stop receiving data for this user
            print("Disconnection")
            return
        data = bytes.decode(server_main_socket.recv(2048))
        print("From user " + sender + " : " + data)

#try:
ip = "-1"# 192.168.1.30" # IP address of the remote server, or -1 for local
while True:
    log = input("Do you want to sign up (0) or login (1)?")
    if log == "0":
        signup(ip)
    elif log == "1":
        usr, server_main_socket, server_listen_socket = login(ip)
        if usr != -1:
            start_new_thread(listen_for_input, ()) # Thread that listens to the client's inputs and sends them to their recipient
            start_new_thread(listen_for_messages, ()) # Thread that listens to the inputs from the server or other clients and displays them
            while not disconnection: # While the user doesn't want to be disconnected, we wait
                pass
            print("You are now disconnected")
            disconnection = False
#finally:
    #server_main_socket.close()
