import sqlite3
import datetime
import threading

sql_lock = threading.Lock()

def get_portnum():  # Obtains port number to listen on for requests and connections. If none available- uses default
    try:
        with open("myport.info","r") as f:  #Read port number for server to listen on
            portnum=f.read().strip()
    except (FileNotFoundError,OSError):
        print("Warning. Could not find or open file myport.info. Proceeding with port number 1357") #Default port
        portnum=1357
    if not portnum.isdigit():
        print("Warning. Unable to read port number from file myport.info. No port number is available. Proceeding with port number 1357")
        portnum=1357
    return portnum

def initialize_database():  #On the servers first execution, the 'clients' table and the 'messages' table are created- to store relevant data
    connecter = sqlite3.connect("defensive.db", timeout=5)
    cursor = connecter.cursor()
    try:
        cursor.execute("CREATE TABLE IF NOT EXISTS clients (ID BLOB, UserName TEXT, PublicKey BLOB, LastSeen TIMESTAMP)")
        cursor.execute("CREATE TABLE IF NOT EXISTS messages (MessageID INTEGER, ReceiverID BLOB, SenderID BLOB, Type INTEGER, Content BLOB)")
    except Exception as e:
        print(f"Error making table: {e}")
        exit()  #If the table/s cannot be created, the server cannot run, so we exit here
    connecter.commit()
    connecter.close()

def update_time(id):    #Server keeps a log (LastSeen) of when every user last made a request. Stored in the database
    with sql_lock:
        connector = sqlite3.connect("defensive.db", timeout=5)
        cursor = connector.cursor()
        cursor.execute("""UPDATE clients SET LastSeen = ? WHERE ID = ?""", (datetime.datetime.now().isoformat(), id))
        connector.commit()
        connector.close()

def validate_header(ID,version,opcode): #Validates that the header fields are all valid, as defined in the project instructions
    if(version not in (1,2) or opcode not in (600,601,602,603,604)):  #Validates version and opcode
        return False
    with sql_lock:
        with sqlite3.connect("defensive.db", timeout=5) as connector:
            cursor=connector.cursor()
            cursor.execute("SELECT 1 FROM clients WHERE ID = ?",(ID,))
            result = cursor.fetchone()
    return (result is not None or opcode==600)   # Validates ID exists (unless this is a signup request)
