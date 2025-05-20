#include "Includes.h"
#include <algorithm>
#include <limits>

void handle_client(std::string server_address, std::string server_port) {
	std::string hex_uuid, base64key, pubkey, username, request, filepath = "me.info";
	std::vector<uint8_t> UUID_buffer;
	std::string greeting_message = R"(MessageU client at your service.

110) Register
120) Request for clients list
130) Request for public key
140) Request for waiting messages
150) Send a text message
151) Send a request for symmetric key
152) Send your symmetric key
153) Send a file
0) Exit client
?)";

	if (std::filesystem::exists(filepath)) {  //If user file already exists- read user info from the file
		try {
			read_info_from_file(filepath, UUID_buffer, base64key, username);
		}
		catch (std::runtime_error& e) {	//If error reading info from file- exit the program.
			std::cout << e.what() << std::endl;
			exit(1);
		}
	}
	else {	//Create user public key and private key, to be stored upon signup
		RSAPrivateWrapper rsapriv;
		pubkey = rsapriv.getPublicKey();
		RSAPublicWrapper rsapub(pubkey);
		std::string regkey = rsapriv.getPrivateKey();
		base64key = Base64Wrapper::encode(rsapriv.getPrivateKey());
	}
	
	boost::asio::io_context io_context;
	tcp::socket s(io_context);
	tcp::resolver resolver(io_context);
	try {
		boost::asio::connect(s, resolver.resolve(server_address, server_port));	//Attempts to connect to server
	}
	catch (const std::exception&) {
		std::cout << "Error. Could not connect to server. Please try again soon.\n";
		exit(1);
	}
	std::cout << greeting_message << "\n";
	std::unordered_map<std::string, bool>NameSymkeyStatus;
	std::unordered_map <std::string, std::array<uint8_t, 16>> NameIDMap;
	std::map <std::array<uint8_t, 16>, std::string> IDNameMap;
	std::unordered_map <std::string, std::string> NamePubkeyMap;
	std::unordered_map<std::string, std::string>NameSymmKeyMap;
	while (true) {
		std::cin >> request;	//Client enters request- valid choices are 110,120,130,140,150,151,152,153,0
		if (std::cin.fail()) {
			std::cout << "Invalid choice! Please enter one of the choices provided in the console \n";
			std::cin.clear();
			std::cin.ignore(1000, '\n');
			continue;
		}
		if (request == "110") {  //Signup
			if (std::filesystem::exists(filepath))	//User cannot signup from device if he already signed up (and has a me.info file)
				std::cout << "Error! You already are a registered user for this service. please enter a different option\n";
			else {
				try {
					signup(s, username, hex_uuid, UUID_buffer, pubkey); //Send request to server
					create_client_info_file(filepath, username, hex_uuid, base64key);	//If signup is successful- store user data in a file
					std::cout << "Welcome! You have successfully signed up to the service\n";
				}
				catch(std::runtime_error& e){
					std::cout << e.what() << std::endl;
					std::cout << greeting_message << "\n";
					continue;
				}
			}
			std::cout << greeting_message << "\n";
			continue;
		}
		else if (request == "120") {  //Get clients list
			if (std::filesystem::exists(filepath)) {
				try {
					get_clients_list(s, UUID_buffer, NameIDMap, IDNameMap, NamePubkeyMap, NameSymkeyStatus);  //Send request to server
					std::array<uint8_t, 16> UUID_arr = {};
					std::copy(UUID_buffer.begin(), UUID_buffer.end(), UUID_arr.begin());
					NameIDMap[username] = UUID_arr;  //These lines store and map all the users names, ID's, and keys (in the function it is done for everyone)
					IDNameMap[UUID_arr] = username;
					NamePubkeyMap[username] = "0000";
					NameSymkeyStatus[username] = false;	//status- didnt receive user's public key yet
					std::cout << greeting_message << "\n";
					continue;
				}
				catch (std::runtime_error& e) {
					std::cout << e.what() << std::endl;
					std::cout << greeting_message << "\n";
					continue;
				}
			}
			else {
				std::cout << "Error in choice, you must sign up before using the service. Please sign up using code 110\n";
				continue;
			}
		}
		else if (request == "130") {  //Get client public key
			if (std::filesystem::exists(filepath)) { //Cant do any operation until signed up
				if (NameIDMap.empty()) { //This means the list of clients wasnt received yet, and user cannot use the service until they receive that list
					std::cout << "Error. You cannot request a public key before getting the list of existing clients. You can get the list by choosing 120 in the menu\n";
					std::cout << greeting_message << "\n";
					continue;
				}
				std::string Name_For_Pubkey;
				std::cout << "Please enter the name of the user whos public key you wish to request:\n";
				std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
				std::getline(std::cin, Name_For_Pubkey);	//Trim whitespaces in input
				Name_For_Pubkey = trim(Name_For_Pubkey);
				try {
					std::array<uint8_t, 16>ID_For_Pubkey = NameIDMap.at(Name_For_Pubkey);	//Try finding client with the name the user chose. Map name to ID for server request
					std::vector<uint8_t>pubkey;
					try {
						request_public_key(s, UUID_buffer, ID_For_Pubkey, NamePubkeyMap, Name_For_Pubkey, pubkey);  //Send request to server
						std::cout << "Public key received\n\n" << greeting_message << "\n";
						continue;
					}
					catch (std::runtime_error& e) {
						std::cout << e.what() << std::endl;
						std::cout << greeting_message << "\n";
						continue;
					}
				}
				catch (const std::out_of_range&) { //If no such client- print error, and wait for next request
					std::cerr << "Error. Operation failed. Could not find requested user. Please choose a different operation\n";
					std::cout << greeting_message << std::endl;
					continue;
				}

			}
			else {
				std::cout << "Error in choice, you must sign up before using the service. Please sign up using code 110\n";
				continue;
			}
		}
		else if (request == "140") {  //Receive my messages
			if (std::filesystem::exists(filepath)){  //Cant do any operation until signed up
				if (NameIDMap.empty()) {  //This means the list of clients wasnt received yet, and user cannot use the service until they receive that list
					std::cout << "Error. You cannot request to view messages before getting the list of existing clients. You can get the list by choosing 120 in the menu\n";
					std::cout << greeting_message << "\n";
					continue;
				}
				try {
					get_messages(s, UUID_buffer, IDNameMap, base64key, NameSymkeyStatus, NameSymmKeyMap);  //Send request to server
					std::cout << greeting_message << "\n";
					continue;
				}
				catch (std::runtime_error& e) {
					std::cout << e.what() << std::endl;
					std::cout << greeting_message << "\n";
					continue;
				}
			}
			else {
				std::cout << "Error in choice, you must sign up before using the service. Please sign up using code 110\n";
				continue;
			}
		}
		else if (request == "150" || request == "151" || request == "152" || request == "153") {  //Send message to client
			if (std::filesystem::exists(filepath)) { //Cant do any operation until signed up
				if (NameIDMap.empty()) {  //This means the list of clients wasnt received yet, and user cannot use the service until they receive that list
					std::cout << "Error. You cannot send any messages before getting the list of existing clients. You can get the list by choosing 120 in the menu\n";
					std::cout << greeting_message << "\n";
					continue;
				}
				std::string Name_For_Message;
				std::cout << "Please enter the name of the user who you would like to send a message to:\n";
				std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
				std::getline(std::cin, Name_For_Message);
				Name_For_Message = trim(Name_For_Message);	//Trim whitespace of name entered
				try {
					std::array<uint8_t, 16>ID_For_Message = NameIDMap.at(Name_For_Message);	//Try to find user in the list. Map name to ID for server request
					std::string string_pubkey = NamePubkeyMap.at(Name_For_Message);	//Get chosen client's public key

					if (request == "150" || request == "153") {  //To send a text message or a file
						if (NameSymkeyStatus[Name_For_Message] == false) { //Indicates that the users dont share a symmetric key- so they cant send messages yet
							std::cout << "Error. You cannot send a text message or file to a different user until you share a symmetric key with them. You can request they generate a key for you, by choosing 151 from the main menu.\n";
							std::cout << greeting_message << "\n";
							continue;
						}
						std::string symmetric_key = NameSymmKeyMap[Name_For_Message];  //otherwise-get the symmetric key
						int type = (request == "150") ? 3 : 4;  //Message type (for sending a text message, or a file)
						try {
							send_message_to_client(s, UUID_buffer, type, ID_For_Message, symmetric_key, Name_For_Message, NameSymmKeyMap);  //Send request to server
						}
						catch (std::runtime_error& e) {
							std::cout << e.what() << std::endl;
							std::cout << greeting_message << "\n";
							continue;
						}
					}
					if (request == "151") { //Sending a request for a symmetric key
						try {
							send_message_to_client(s, UUID_buffer, 1, ID_For_Message, string_pubkey, Name_For_Message, NameSymmKeyMap); //Send request to server
						}
						catch (std::runtime_error& e) {
							std::cout << e.what() << std::endl;
							std::cout << greeting_message << "\n";
							continue;
						}
					}
					if (request == "152") {  //sending a symmetric key
						if (string_pubkey == "0000") {  //This indicates the user doesnt have the other clients public key yet. Therefore- he cannot send a symmetric key yet
							std::cout << "Error. You cannot send a symmetric key to a user if you do not have their public key yet. You can obtain their public key with request 130\n";
							std::cout << greeting_message << "\n";
							continue;
						}
						try {
							send_message_to_client(s, UUID_buffer, 2, ID_For_Message, string_pubkey, Name_For_Message, NameSymmKeyMap); //Send request to server
							NameSymkeyStatus[Name_For_Message] = true;  //Update status- user and receiving client now share a symmetric key
						}
						catch (std::runtime_error& e) {
							std::cout << e.what() << std::endl;
							std::cout << greeting_message << "\n";
							continue;
						}
					}
					std::cout << greeting_message << "\n";
					continue;
				}
				catch (const std::out_of_range&) {  //Couldnt find selected user-print error, and wait for next request
					std::cerr << "Error. Operation failed. Could not find requested user. Please enter a different operation\n\n";
					std::cout << greeting_message << "\n";
					continue;
				}
			}
			else {
				std::cout << "Error in choice, you must sign up before using the service. Please sign up using code 110\n";
				continue;
			}
		}
		else if (request == "0") {	//Request to quit
			std::cout << "Closing messaging service...\nGoodbye.";
			s.close();  //Closes socket and exits
			exit(1);
		}
		else
			std::cout << "Invalid choice! Please enter one of the choices provided in the console \n";
			std::cout << greeting_message << std::endl;		
	}
}

/*This functions takes an std::string and returns it without the leading and trailing whitespaces*/
std::string trim(const std::string& str) {
	size_t start = str.find_first_not_of(" \t\n\r");
	if (start == std::string::npos) return "";

	size_t end = str.find_last_not_of(" \t\n\r");
	return str.substr(start, (end - start + 1));
}

/*This function receives parameters and builds a request header (to send to server) from the parameters. Little endian format*/
std::vector<uint8_t> build_request_header(std::vector<uint8_t>ID, uint8_t version, uint16_t code, uint32_t payload_size) {
	std::vector<uint8_t>buffer;
	buffer.insert(buffer.end(), ID.begin(), ID.end());
	buffer.push_back(version);
	buffer.push_back(code & 0xFF);
	buffer.push_back((code >> 8) & 0xFF);
	buffer.push_back(payload_size & 0xFF);
	buffer.push_back((payload_size >> 8) & 0xFF);
	buffer.push_back((payload_size >> 16) & 0xFF);
	buffer.push_back((payload_size >> 24) & 0xFF);
	return buffer;
}
