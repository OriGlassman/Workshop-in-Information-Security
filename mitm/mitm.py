import socket
import threading, thread
import select
import re
import errno
from socket import error as socket_error
from manage_conn_table import set_mitm_port, get_mitm_port, create_ftp_entries

MAX_PACKET = 32768
SERVER_IP = "10.1.2.2"
CLIENT_IP = "10.1.1.1"
FW_IP_SERVER_INTERFACE = "10.1.2.3"
FW_IP_CLIENT_INTERFACE = "10.1.1.3"
HTTP_PORT = "80"
FTP_PORT = "21"
THINVNC_PORT = "8080"
SMTP_PORT = "25"

HTTP_MITM_LISTENING_PORT = 800
FTP_MITM_LISTENING_PORT = 210
THINVNC_MITM_LISTENING_PORT = 8081
SMTP_MITM_LISTENING_PORT = 250


#
# The http man in the middle user space program
#
def run_mitm_http():
    mitm_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, \
                              socket.IPPROTO_TCP)
    mitm_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    mitm_sock.bind((FW_IP_CLIENT_INTERFACE, HTTP_MITM_LISTENING_PORT))
    mitm_sock.listen(1)
    
    while True:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((FW_IP_SERVER_INTERFACE,0))
        client_sock, client_addr = mitm_sock.accept()
        res = set_mitm_port(SERVER_IP, HTTP_PORT, CLIENT_IP, str(client_sock.getpeername()[1]), str(server_socket.getsockname()[1]))
        if res is not 0:
            print("Problem occurred setting mitm port")
            break
        try:
            server_socket.connect((SERVER_IP,int(HTTP_PORT)))
        except socket_error as serr:
            client_sock.close()
            if serr.errno == errno.ECONNREFUSED:
                print("Connection refused! Http server is down")
                continue
            else:
                raise serr
            
        socket_list = [server_socket, client_sock]    
        end_connection_client = False
        end_connection_server = False
        invalid_data = False
        while True:
            if (end_connection_client and end_connection_server) or invalid_data:
                break
            read_sockets, write_sockets, error_sockets = select.select(socket_list, [], [])
            for sock in read_sockets:                
                if sock == client_sock:
                    data = client_sock.recv(MAX_PACKET)
                    if data == '':
                        end_connection_client = True
                    else:
                        server_socket.sendall(data) 
                    
                elif sock == server_socket:                        
                    data = server_socket.recv(MAX_PACKET)
                    if data == '':
                        end_connection_server = True
                    if not is_valid_content_type(data) or is_c_code(data):
                        print("Dropping packet! encountered invalid content type or C code")
                        invalid_data = True
                        break
                    if data != '':
                        client_sock.sendall(data)
        client_sock.close()
        server_socket.close()

        
invalid_content_type_values = ["text/csv", "application/zip"]
#
# returns 1 if the header is valid, else 0
#
def is_valid_content_type(response):
    lines = response.splitlines()
    for line in lines:
        line = line.lower()
        if line.startswith("content-type"):
            content_type = line.split(":")
            if len(content_type) != 2:
                print("Empty content-type value!")
                return 1
            else:
                return 0 if content_type[1].strip() in invalid_content_type_values else 1
    return 1
        
#
# The ftp man in the middle user space program
#                
def run_mitm_ftp():
    mitm_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, \
                              socket.IPPROTO_TCP)
    mitm_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    mitm_sock.bind((FW_IP_CLIENT_INTERFACE, FTP_MITM_LISTENING_PORT))
    mitm_sock.listen(1)

    while True:
        # accept connection
        client_sock, client_addr = mitm_sock.accept()

        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((FW_IP_SERVER_INTERFACE,0))
        res = set_mitm_port(SERVER_IP, FTP_PORT, CLIENT_IP, str(client_sock.getpeername()[1]), str(server_socket.getsockname()[1]))
        if res is not 0:
            print("Problem occurred setting ftp mitm port")
            break
        server_socket.connect((SERVER_IP,int(FTP_PORT)))
        
        socket_list = [server_socket, client_sock]
        end_connection_client = False
        end_connection_server = False
        while True:
            if end_connection_client and end_connection_server:
                break
            read_sockets, write_sockets, error_sockets = select.select(socket_list, [], [])
            for sock in read_sockets:                
                if sock == server_socket:
                    data = server_socket.recv(MAX_PACKET)
                    if data == '':
                        end_connection_server = True
                    client_sock.sendall(data)
                    
                elif sock == client_sock:
                    data = client_sock.recv(MAX_PACKET)
                    if data == '':
                        end_connection_client = True
                    le_port = is_PORT_request(data)
                    if (le_port != 0):
                        create_ftp_entries(str(le_port))
                    server_socket.sendall(data)    
                    
        server_socket.close()
        client_sock.close()
    
#
# Checks if it is a port request and if so returns the port
#
def is_PORT_request(request):
    if request.startswith("PORT"):
        request = request.split(",")
        if len(request) != 6:
            print("Error: PORT request is in the wrong format")
            
        try: 
            le_port = 256*int(request[4]) + int(request[5])
            return le_port
        except ValueError:
            print("Error: received an error converting ports from string to int")
            return 0
    return 0

#
# The http man in the middle user space program
#
def run_mitm_thinvnc():
    mitm_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, \
                              socket.IPPROTO_TCP)
    mitm_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    mitm_sock.bind((FW_IP_CLIENT_INTERFACE, THINVNC_MITM_LISTENING_PORT))
    mitm_sock.listen(1)

    while True:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((FW_IP_SERVER_INTERFACE,0))
        client_sock, client_addr = mitm_sock.accept()
        res = set_mitm_port(SERVER_IP, THINVNC_PORT, CLIENT_IP, str(client_sock.getpeername()[1]), str(server_socket.getsockname()[1]))
        if res is not 0:
            print("Problem occurred setting mitm port")
            break

        try:
            server_socket.connect((SERVER_IP,int(THINVNC_PORT)))
        except socket_error as serr:
            client_sock.close()
            if serr.errno == errno.ECONNREFUSED:
                print("Connection refused! ThinVNC server is down.")
                continue
            else:
                raise serr
                
        socket_list = [client_sock, server_socket]
        end_connection_client = False
        end_connection_server = False
        invalid_request = False
        while True:
            if (end_connection_client or end_connection_server) or invalid_request:
                break
            read_sockets, write_sockets, error_sockets = select.select(socket_list, [], [])

            for sock in read_sockets:
            
                if sock == client_sock:
                    data = client_sock.recv(MAX_PACKET)
                    if data == '':
                        end_connection_client = True
                        break
                    elif not is_valid_url_request(data):
                        print("Detected ThinVNC exploit attack, blocking it...")
                        invalid_request = True
                        break
                    server_socket.sendall(data)
                    

                elif sock == server_socket:
                    data = server_socket.recv(MAX_PACKET)
                    if data == '':
                        end_connection_server = True
                    client_sock.sendall(data)           
        client_sock.close()
        server_socket.close()
#
# Checks for ThinVnc exploit url
#
def is_valid_url_request(request):
    if request.startswith("GET"):
        url = request.splitlines()[0]
        if ".." in url:
            return False
        else:
            return True
    else:
        return True
    
#
# The smtp man in the middle user space program
#    
def run_mitm_smtp():
    mitm_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, \
                              socket.IPPROTO_TCP)
    mitm_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    mitm_sock.bind((FW_IP_CLIENT_INTERFACE, SMTP_MITM_LISTENING_PORT))
    mitm_sock.listen(1)

    while True:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((FW_IP_SERVER_INTERFACE,0))
        client_socket, client_addr = mitm_sock.accept()
        res = set_mitm_port(SERVER_IP, SMTP_PORT, CLIENT_IP, str(client_socket.getpeername()[1]),       str(server_socket.getsockname()[1]))
        if res is not 0:
            print("Problem occurred setting mitm port")
            break

        try:
            server_socket.connect((SERVER_IP,int(SMTP_PORT)))
        except socket_error as serr:
            client_socket.close()
            if serr.errno == errno.ECONNREFUSED:
                print("Connection refused! SMTP server is down.")
                continue
            else:
                raise serr
        
        socket_list = [client_socket, server_socket]
        end_connection_client = False
        end_connection_server = False
        invalid_request = False
        while True:
            if end_connection_client and end_connection_server or invalid_request:
                break
            read_sockets, write_sockets, error_sockets = select.select(socket_list, [], [])

            for sock in read_sockets:
            
                if sock == client_socket:
                    data = client_socket.recv(MAX_PACKET)
                    if data == '':
                        end_connection_client = True
                    elif is_c_code(data):
                        print("Dropping packet! encountered C code")
                        invalid_request = True
                        break
                    server_socket.sendall(data)
                    

                elif sock == server_socket:
                    data = server_socket.recv(MAX_PACKET)
                    if data == '':
                        end_connection_server = True
                    client_socket.sendall(data)   
        server_socket.close()
        client_socket.close()
           
#
# Checks if the data that is being transferred is c code
#
def is_c_code(data):
    total_score = 0
    lines = data.split("\r\n")
    if len(lines) == 0:
        lines = data.split("\n")
        
    is_java_or_python = re.compile(r"import|package\s(.*?);?") # searching for import in python (without semicolon) and with semicolon (in java) or package declaration in java
    for line in lines: 
        if is_java_or_python.search(line): # This significantly reduces the false positive on java or python files
            print("Found java or python code")
            total_score = 0
            break

        score = get_likelihood_for_c_code(line)
        total_score += score
        if total_score >= 100:
            break        
    return True if total_score >= 100 else False
#
# returns a score >= 0, for the likelihood that this is indeed C code
#
def get_likelihood_for_c_code(line):
    score = 0
    score += contains_include(line)
    score += contains_define(line)
    score += endswith_semi_colons(line) 
    score += contains_function_call(line)
    score += contains_comment(line)
    score += has_main(line)
    score += has_printf(line)
    score += has_memory_alloc_functions(line)
    score += has_string_functions(line)
    return score
#
# Checks if the line contains any basic common string library function in C. If so, returns 100 else 0
#
def has_string_functions(line):
    return 100 if "strcmp(" in line or \
        "strcpy(" in line or \
        "strlen(" in line or \
        "strncat(" in line or \
        "strncmp(" in line or \
        "strncpy(" in line \
        else 0
#
# Checks if the line contains any basic common memory allocation function in C. If so, returns 100 else 0
#
def has_memory_alloc_functions(line):
    return 100 if "malloc(" in line or "realloc(" in line or "calloc(" in line else 0

#
# Checks if the line contains a "#include", if so returns 90 else 0.
#
def contains_include(line):
    return 90 if line.lstrip().startswith("#include") else 0

#
# Checks if the line contains a "#define", if so returns 100 else 0.
#
def contains_define(line):
    return 100 if line.lstrip().startswith("#define") else 0

#
# Checks if the line ends with ";", if so returns 10 else 0.
#
def endswith_semi_colons(line):
    return 10 if line.rstrip().endswith(";") else 0

#
# Checks if the line include a function call, i.e, "some_func()", if so returns 20 else 0.
# Note that there is no whitespace between the parenthesis.
def contains_function_call(line):
    is_function_regex = re.compile(r"[^\s]\(.*?\)")
    match = is_function_regex.search(line)
    return 20 if match else 0
#
# Checks if the line contains C comment, if so returns 20 else 0.
#
def contains_comment(line):
    return 20 if "//" in line or "/*" in line or "*/" in line else 0
#
# Checks if the line contains C main function, if so returns 100 else 0.
#
def has_main(line):
    return 100 if "int main(" in line or "void main(" in line else 0

#
# Checks if the line contains C printf variation function, if so returns 100 else 0.
#
def has_printf(line):
    return 100 if "printf(" in line or "fprintf(" in line else 0
        
                             

#
# Runs the listeners as threads
#
if __name__ == '__main__': 
    http_thread = threading.Thread(target=run_mitm_http)
    ftp_thread = threading.Thread(target=run_mitm_ftp)
    thinvnc_thread = threading.Thread(target=run_mitm_thinvnc)
    smtp_thread = threading.Thread(target=run_mitm_smtp)
    http_thread.start()
    ftp_thread.start()
    thinvnc_thread.start()
    smtp_thread.start()
    