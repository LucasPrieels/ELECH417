import socket, time

def connect_to_server(ip):
    s = socket.socket()    # Remote socket
    host = socket.gethostname() # Remote address (here same as local since local tests)
    port = 9999 # Remote port number
    if ip == "-1": # If local
        ip = host
    s.connect((ip,port))
    return s

def login(ip):
    print("####### LOGIN #######")
    usr = input("Username : ")
    pswd = input("Password : ")
    server_socket = connect_to_server(ip)

    server_socket.send(str.encode("0")) # Code stating we want to login
    server_socket.send(str.encode(str(usr) + " " + str(pswd))) # str.encode() to transform the string into bytes
    
    ans = bytes.decode(server_socket.recv(1)) # 1 byte is enough
    if ans == "0":
        print("Username unkown\n")
        return -1
    elif ans == "1":
        print("Password incorrect\n")
        return -1
    elif ans == "2":
        print("Connection successful\n")
        return usr
    else:
        raise Exception("Unexpected answer")
        
def signup(ip):
    print("####### SIGNUP #######")
    usr = input("Username : ")
    pswd = input("Password : ")
    server_socket = connect_to_server(ip)
    
    server_socket.send(str.encode("1")) # Code stating we want to sign up
    server_socket.send(str.encode(str(usr) + " " + str(pswd))) # str.encode() to transform the string into bytes
    
    ans = bytes.decode(server_socket.recv(1)) # 1 byte is enough, it's the status of the query
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
        login(ip)
#finally:
    #server_socket.close()
