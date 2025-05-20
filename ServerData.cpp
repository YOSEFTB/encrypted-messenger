#include "Includes.h"
#include <algorithm>

void get_clients_list(tcp::socket& s, const std::vector<uint8_t>& UUID, std::unordered_map<std::string, std::array<uint8_t, 16>>& Name_ID_Pair, std::map<std::array<uint8_t, 16>, std::string>& ID_Name_Pair, std::unordered_map <std::string, std::string>& NamePubkeyMap, std::unordered_map <std::string, bool>& NameSymkeyStatus) {
	std::vector<uint8_t>buffer = build_request_header(UUID, 2, 601, 0);  //Build header for request for public key

	try {
		boost::asio::write(s, boost::asio::buffer(buffer));  //Send request to server
	}
	catch (const std::exception&) {
		throw std::runtime_error("Error. Coundn't complete request\n");
	}
	buffer.clear();
	char buff[7];
	try {
		boost::asio::read(s, boost::asio::buffer(buff, 7));  //Read header for response
	}
	catch (const std::exception&) {
		throw std::runtime_error("Error. Coundn't receive server response\n");
	}
	uint8_t serv_version = buff[0];
	uint16_t serv_opcode;
	uint32_t serv_payload_size;				//Parse header, in little endian format
	serv_opcode = boost::endian::load_little_u16(reinterpret_cast<const unsigned char*>(buff + 1));
	serv_payload_size = boost::endian::load_little_u32(reinterpret_cast<const unsigned char*>(buff + 3));

	if (serv_opcode == 9000) {  //Server error
		throw std::runtime_error("Server responded with an error\n");
	}
	else if (serv_opcode != 2101) {   //Error in response
		throw std::runtime_error("Error in processing server response\n");
	}

	if (serv_payload_size == 0) {  //no other users signed up = payload is 0
		std::cout << "There are no users signed up for the service (excluding you)\n";
		return;
	}

	std::cout << "List of other clients signed up for the messaging service below-\n\n";
	std::array<uint8_t, 271>list_of_names;		//Store each users data in the array (ID+UsernameD)
	int counter = 0;
	int num_of_contacts = serv_payload_size / (255 + 16);  //Calculate num of clients, based on the payload size
	while (counter < num_of_contacts) {  //Read until all clients have been read
		try {
			boost::asio::read(s, boost::asio::buffer(list_of_names));
		}
		catch (const std::exception&) {
			throw std::runtime_error("Error. Coundn't receive server response (list of clients)\n");
		}
		std::array<uint8_t, 16> client_id;
		std::copy(list_of_names.begin(), list_of_names.begin() + 16, client_id.begin());  //Store the ID in the array
		auto name_end = std::find(list_of_names.begin() + 16, list_of_names.end(), '\0');  //Find the null terminator which delimits the name
		if (name_end == list_of_names.end()) {  //name_end==end() means there is no null terminator -> error in format 
			throw std::runtime_error("Invalid client name format : missing null terminator. Terminatined operation");
		}
		std::string name(list_of_names.begin() + 16, name_end);  //Store the name (up until the '\0') in the std::string

		if (Name_ID_Pair[name] != client_id) {   //Only updates status of clients not read yet. This ensures old public and symmetric keys are kept
			Name_ID_Pair[name] = client_id;		//Create a map from users name to their ID
			ID_Name_Pair[client_id] = name;		//From their ID to their name
			NamePubkeyMap[name] = "0000";	//Initialize their public key to be 0000 (to denote not having their key yet, this will update upon getting the key)
			NameSymkeyStatus[name] = false;		//Denotes status of users symmetric key with other user. Default is false - not having one
		}

		std::cout << name << std::endl;
		counter++;  //Counts clients read
	}
	std::cout << std::endl;
	std::cout << "There are no more contacts to be displayed\n";
}

void request_public_key(tcp::socket& s, const std::vector<uint8_t>& UUID, const std::array<uint8_t, 16>& ID_For_Pubkey, std::unordered_map<std::string, std::string>& NamePubkeyMap, std::string Name_For_Pubkey, std::vector<uint8_t>& pubkey) {
	std::vector<uint8_t>buffer = build_request_header(UUID, 2, 602, 16);  //Builds header for public key request
	buffer.insert(buffer.end(), ID_For_Pubkey.begin(), ID_For_Pubkey.end());  //ID of requested user

	try {
		boost::asio::write(s, boost::asio::buffer(buffer));  //Send request to server
	}
	catch (const std::exception&) {
		throw std::runtime_error("Error. Coundn't complete request\n");
	}

	char buff[7];
	try {
		boost::asio::read(s, boost::asio::buffer(buff, 7)); //Read response header
	}
	catch (const std::exception&) {
		throw std::runtime_error("Error. Coundn't receive server respomse\n");
	}
	uint8_t serv_version = buff[0];
	uint16_t serv_opcode;						//Parse the header, in little endian format
	uint32_t serv_payload_size;
	serv_opcode = boost::endian::load_little_u16(reinterpret_cast<const unsigned char*>(buff + 1));
	serv_payload_size = boost::endian::load_little_u32(reinterpret_cast<const unsigned char*>(buff + 3));

	if (serv_opcode == 9000) {		//Server error
		throw std::runtime_error("Server responded with an error\n");
	}
	else if (serv_opcode != 2102) {		//Error processing response
		throw std::runtime_error("Error in processing server response\n");
	}

	std::vector<uint8_t>ID_Pubkey_Vector(serv_payload_size);  //Store the servers response- the ID and public key of the user
	try {
		boost::asio::read(s, boost::asio::buffer(ID_Pubkey_Vector.data(), serv_payload_size));
	}
	catch (const std::exception&) {
		throw std::runtime_error("Error. Coundn't receive server response\n");
	}
	std::vector<uint8_t>Pubkey_Vector(ID_Pubkey_Vector.begin() + 16, ID_Pubkey_Vector.end()); //The public key
	std::string pubkey_string(Pubkey_Vector.begin(), Pubkey_Vector.end());  //Stored in std::string
	NamePubkeyMap[Name_For_Pubkey] = pubkey_string;  //Stored in the map, from Username to public key
	return;
}