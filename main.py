import initialize_server
import server

def main(): #Main function of the program, to initialize the server. 
    portnum=server.get_portnum()
    server.initialize_database()
    initialize_server.start_server(int(portnum))

if(__name__ == "__main__"):
    main()