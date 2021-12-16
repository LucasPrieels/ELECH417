import socket, time

def connect_to_server():
    s = socket.socket()    # Remote socket
    host = socket.gethostname() # Remote address (here same as local since local tests)
    port = 9999 # Remote port number
    s.connect((host,port))
    return s

def login(s):
    usr = input("Username : ")
    pswd = input("Password : ")

    s.send(str.encode(str(usr) + " " + str(pswd))) # str.encode() to transform the string into bytes
    
    ans = bytes.decode(s.recv(1)) # 1 byte is enough
    if ans == "0":
        print("Username unkown")
        return -1
    elif ans == "1":
        print("Password incorrect")
        return -1
    elif ans == "2":
        print("Connection successful")
        return usr
    else:
        print("Error")
        return -1

server_socket = connect_to_server()
login(server_socket)
server_socket.close()
