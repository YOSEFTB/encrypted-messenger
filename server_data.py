from includes import signup
import struct
import sqlite3
import threading

sql_lock = threading.Lock()

def send_error_response(sock,version):  #General response that the server sends for all errors- communication, signup, syntax, deviation from protocol.
    opcode=9000
    payload_length=0
    format_string='<BHI'
    packed_data=struct.pack(format_string,version,opcode,payload_length)
    try:
        sock.send(packed_data)
    except Exception as e:  # If the server cant even send the error message to client- it disconnects from client
        with sql_lock:
            print(f"Error. Could not send error message. {e}")
        exit()
    clear_socket(sock)

def clear_socket(sock): # When server receives an invalid input, this flushes the socket to remove all the leftover input the user sent
    sock.setblocking(False)
    try:
        while sock.recv(4096):  # Read and discard any leftover data
            pass
    except BlockingIOError:
        pass  # No more data left to read
    sock.setblocking(True)

def send_client_pubkey(sock,serv_version,payload_size,opcode):  # Sends a user a public key of a user, upon request
    with sql_lock:
        connector = sqlite3.connect("defensive.db", timeout=5)
        cursor = connector.cursor()
        seeked_id=sock.recv(payload_size)
        cursor.execute("SELECT PublicKey FROM clients WHERE ID = ?", (seeked_id,))  # Finds requested users public key
        pubkey=cursor.fetchone()[0] # If no such client is found, accessing [0] will raise an error. The server will send an error response
        id_len,key_len=len(seeked_id),len(pubkey)
        connector.close()
    pubkeylen=160
    format_string=f'<BHI{16}s{pubkeylen}s'
    packed_data=struct.pack(format_string,serv_version,opcode,id_len+key_len,seeked_id,pubkey)
    sock.send(packed_data)

def get_row_count():    # Returns the number of rows in the clients database
    connector = sqlite3.connect("defensive.db", timeout=5)
    cursor = connector.cursor()
    cursor.execute("SELECT COUNT(*) FROM clients;")
    row_count = cursor.fetchone()[0]
    connector.close()
    return row_count

def send_clients_list(sock,serv_version,opcode,id): # Sends a list of the clients to user, upon request
    row_count=get_row_count()-1
    client_info_length=271
    payload_length=row_count*client_info_length
    format_string=f'<BHI'
    packed_data=struct.pack(format_string,serv_version,opcode,payload_length)
    sock.send(packed_data)
    with sql_lock:
        connector = sqlite3.connect("defensive.db", timeout=5)
        cursor = connector.cursor()
        cursor.execute("SELECT UserName, ID FROM clients")
        for row in cursor: # Iterate over the result one row at a time
            uname, client_id = row
            if(id==client_id):  # Doesnt send the info of the user himself
                continue
            name_bytes=signup.pack_username(uname)  # Extracts the users name, and pads it with a \0 terminator
            name_length=len(name_bytes)
            id_length=len(client_id)
            format_string=f'<{id_length}s{name_length}s'
            packed_data=struct.pack(format_string,client_id,name_bytes)
            sock.send(packed_data)
        connector.close()