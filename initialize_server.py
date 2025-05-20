from includes import signup,message_handling,server_data,server
import datetime
import socket 
import struct 
import sqlite3 
import threading
import uuid
import random

print_lock = threading.Lock()

def start_server(portnum):  #Initializes the server, and when accepting a connection- spawns a new thread for that client
    print("started server...")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("localhost", portnum))
    server.listen()
    print(f"Server is listening on port {portnum}...")
    while True:
        conn, addr = server.accept()    #Each client gets their own socket for writing and reading data
        thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
        thread.start()

def recv_all(sock,size):    #Loops when needing to ensure all of the data is read- will keep reading until 'size' bytes read. 
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:   #or the data is shorter then expected- the function will return with the data it received
            return data
        data += chunk
    return data

def read_and_parse_data(sock):  #This function reads the beginning of the user request, and parses the different fields.
    try:
        data = recv_all(sock, 23)
    except (OSError,ConnectionResetError) as e:  #Terminates thread if client disconnects or breaks the connection
        with print_lock:
            print(e)
        exit()
    if(not data):
        with print_lock:
            print("A client disconnected gracefully")
        exit()
    if(len(data)<23):   #If less than 23 bytes are sent, the message is invalid/corrupted. The server notifies the client
        return 0,0,0,0  #Returns a 0 tuple to ensure the caller func will detect an error and send to user.
    
    # Unpack the data: 16-byte ID (as bytes), 1-byte version, 2-byte opcode, and payload size
    id_bytes = (data[:16]) 
    version = data[16] 
    opcode = struct.unpack('<H', data[17:19])[0]
    payload_size=struct.unpack('<I',data[19:23])[0]
    if(server.validate_header(id_bytes,version,opcode)):   # Validates the ID,version, and opcode
        return id_bytes, version, opcode, payload_size
    else:
        return 0,0,0,0  #As mentioned, func will return 0 tuple to ensure error is detected

def handle_client(conn,addr):   #This function processes the clients actual request
    serv_version=2
    with print_lock:
        print(f"Client connected from {addr}")
    while True:
        id,client_version,opcode,payload_size = read_and_parse_data(conn)   #The values returned from the earlier func,that parses the header
        if(opcode==0):  #If an error was detected in the request, an error message is sent to client
            with print_lock:
                print("Error in client input.")
            server_data.send_error_response(conn,serv_version)
            continue    #and the server waits for the next request

        server.update_time(id) #update the 'last seen' data

        if(opcode==600):    #Request to sign up
            username,public_key = signup.get_username(conn,payload_size)    #Server makes sure that the name the client chose isnt in use
            if signup.username_exists(username):
                with print_lock:
                    print(f"Error signing up")
                server_data.send_error_response(conn,serv_version)
            else:
                try:
                    signup.store_user_data(conn,serv_version,username,public_key)   #Store username and user pub. key in the server
                except Exception as e:
                    with print_lock:
                        print(f"Error signing up: {e}")
                    server_data.send_error_response(conn,serv_version)  #Send error message (code 9000) if any errors occur

        elif(opcode==601):  #Client requested the  list of other clients (clients name is left out)
            try:
                server_data.send_clients_list(conn, serv_version, 2101, id)
            except Exception as e:
                with print_lock:
                    print(f"Error sending list: {e}")
                server_data.send_error_response(conn,serv_version)  #Send error message (code 9000) if any errors occur

        elif(opcode==602):  #Client requests a users public key
            try:
                server_data.send_client_pubkey(conn,serv_version,payload_size,2102)
            except Exception as e:
                with print_lock:
                    print(f"Error sending public key: {e}")
                server_data.send_error_response(conn,serv_version)  #Send error message (code 9000) if any errors occur

        elif(opcode==603):  #Client requested to send a message to another user
            try:
                receiver_id, message_id = message_handling.receive_message(conn,id)
                message_handling.send_received_message_response(conn,serv_version,receiver_id,message_id,2103)  #Acknowledgment of sent message
            except Exception as e:
                with print_lock:
                    print(f"Error receiving message: {e}")
                server_data.send_error_response(conn,serv_version)  #Send error message (code 9000) if any errors occur

        elif(opcode==604):  #Client requested to view all their messages
            try:
                message_handling.send_messages_to_user(conn,serv_version,2104,id)
            except Exception as e:
                with print_lock:
                    print(f"Error sending messages to user: {e}")
                server_data.send_error_response(conn,serv_version)  #Send error message (code 9000) if any errors occur

        else:   #Opcode is invalid, send error message and wait for the next request
            server_data.send_error_response(conn,serv_version)
            with print_lock:
                    print(f"Invalid user input")
