import struct
import uuid
import sqlite3
import datetime
import threading

# This module handles the signup process, from validating the username, to storing user data in the proper format

sql_lock = threading.Lock()

def get_username(sock,payload_size):    # Extracts users name from data, appends a null terminator, and returns the name
    username_len=255
    payload=sock.recv(payload_size)
    username=payload[:username_len].decode()
    public_key=payload[username_len:]
    username=username.split("\0")[0]+'\0'
    return username,public_key

def store_user_data(sock,serv_version,username,public_key): # Upon signup, store the users data in the client table. Sends acknowledgment
    NEW_ID = uuid.uuid4().bytes # Creates a new UUID for user
    with sql_lock:
        connector = sqlite3.connect("defensive.db", timeout=5)
        cursor = connector.cursor()
        cursor.execute("INSERT INTO clients (ID, UserName, PublicKey, LastSeen) VALUES (?,?,?,?)",(NEW_ID,username,public_key,datetime.datetime.now().isoformat()))
        connector.commit()
        connector.close()
    send_signup_success(sock,serv_version,2100,16,NEW_ID)

def send_signup_success(sock,version,opcode,payload_length,UUID_new):   # Acknowledgment of user signup success
    format_string=f'<BHI{payload_length}s'
    packed_data=struct.pack(format_string,version,opcode,payload_length,UUID_new)
    sock.send(packed_data)

def username_exists(username):  # Returns whether or not the name the user requested to sign up with is already in the system (database)
    with sql_lock:
        connector = sqlite3.connect("defensive.db", timeout=5)
        cursor = connector.cursor()
        cursor.execute("SELECT UserName FROM clients WHERE UserName = ?", (username,))
        result=cursor.fetchone()
        connector.close()
    if result:  # Result is not empty, which means the name is in the database
        return True
    return False

def pack_username(username):    # Pads a name with null terminators, until length 255, which is the protocol required length for username field
    encoded = username.encode()
    return encoded.ljust(255, b'\x00')