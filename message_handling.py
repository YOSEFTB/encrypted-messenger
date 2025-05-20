import struct 
import sqlite3 
import random
import threading

# This module handles messages- receiving them, storing them, and retrieving them. Operations are thread safe using threading and locks

sql_lock = threading.Lock()

def send_received_message_response(sock,serv_version,receiver_id,message_id,opcode):    #Sends acknowledgment that the server received a message from the user
    id_len, message_id_len= len(receiver_id), len(str(message_id))
    format_string=f'<BHI{16}sI'
    packed_data=struct.pack(format_string,serv_version,opcode,id_len+4,receiver_id,message_id)
    sock.send(packed_data)

def receive_message(sock,sender_id):    #Receives message, parses the data, and stores the message in the messages table, to be retrieved later by receiver (upon request)
    message_header=sock.recv(21)
    receiver_client_id=message_header[:16]
    if(not id_exists(receiver_client_id)):  # Checks that the receiver ID is valid
        raise ValueError
    message_type=message_header[16]
    if(message_type not in (1,2,3,4)):  # Checks that the message type is valid
        raise ValueError
    content_size= struct.unpack('<I',message_header[17:21])[0]
    content=sock.recv(content_size)
    message_id= random.randint(1000,0xffffffff) # Generates an ID for the message. 4 bytes, positive
    with sql_lock:
        connector = sqlite3.connect("defensive.db", timeout=5)
        cursor = connector.cursor()
        cursor.execute("INSERT INTO messages (MessageID, ReceiverID, SenderID, Type, Content) VALUES (?,?,?,?,?)",(message_id,receiver_client_id,sender_id,message_type,content))
        connector.commit()
        connector.close()
    return receiver_client_id,message_id

def id_exists(ID):  # Function to determine whether or not an ID exists in the client database
    with sql_lock:
        with sqlite3.connect("defensive.db", timeout=5) as connector:      
            cursor=connector.cursor()
            cursor.execute("SELECT 1 FROM clients WHERE ID = ?",(ID,))
            result = cursor.fetchone()
    return (result is not None)

def send_messages_to_user(sock,serv_version,opcode,id): # Upon request, server sends user messages sent to them. After sending, the server deletes the messages
    connector = sqlite3.connect("defensive.db", timeout=5)
    cursor = connector.cursor()
    with sql_lock:
        cursor.execute("SELECT * FROM messages WHERE ReceiverID = ?", (id,))
        message_count=0
        total_content_length=0
        for row in cursor:
            message_count+=1
            total_content_length=total_content_length+len(row[4])
        payload_size= (25*message_count)+total_content_length  # Calculates the payload size. Each message has a 25 byte header(ClientID, MessageID, Message Type, Message Size) and Content.   

        format_string='<BHI'
        packed_data=struct.pack(format_string,serv_version,opcode,payload_size)
        sock.send(packed_data)

        list_of_sent_messages=[]    #List of sent messages, so they can be deleted after sending them
        cursor.execute("SELECT * FROM messages WHERE ReceiverID = ?", (id,))
        for row in cursor:  # Gets all of users messages from the server, and sends the messages to the user according to protocol
            sender_id=row[2]
            message_id=row[0]
            message_type=row[3]
            content=row[4]
            message_size=len(content)
            format_string=f'<{16}sIBI{message_size}s'
            packed_data=struct.pack(format_string,sender_id,message_id,message_type,message_size,content)
            sock.send(packed_data)
            list_of_sent_messages.append(message_id) #After sending a message- append to list for deleting 
        for message in list_of_sent_messages:   #Delete all messages sent to user
            cursor.execute("DELETE FROM messages WHERE ReceiverID = ? AND MessageID = ?",(id, message))
            connector.commit()
        connector.close()

