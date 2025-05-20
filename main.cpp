#include <string>
#include <iostream>

void extract_server_info(const std::string& filename, std::string& address, std::string& port);
void handle_client(std::string address, std::string port);

/*
This program implements the client side of the MessageU messaging service. Users can sign up for the service using the program.
Users can request the list of all other clients, and send messages to other users. Users can send messages to other clients that are signed up to the service.
The messages are encrypted using RSA and AES encryption and not even the server can read them. The clients can request other users public keys (or their own)
or create symmetric keys to establish secure connections. Users can also request to receive all their messages and read them. Users can disconnect from the service by choosing 0.
The service handles errors and invalid input gracefully, and handles multiple clients simultaneously from different devices using threads.
*/

int main() {		//Main method, to initialize the service and connect to the server
	std::string server_address, server_port;
	try {		//Read server location info from file, if failed to do so, exit program
		extract_server_info("server.info", server_address, server_port);
	}
	catch (std::runtime_error& e) {
		std::cout << e.what() << std::endl;
		exit(1);
	}
	handle_client(server_address, server_port);  //Logic of processing user requests and calling relevant functions to deal with the request
}