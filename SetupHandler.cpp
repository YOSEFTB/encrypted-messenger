#include "Setup.h"
#include <limits>
#include <iomanip>

void extract_server_info(const std::string& filename, std::string& address, std::string& port) {  //Reads server info from the file
	std::string line;
	std::ifstream infile(filename);
	if (!infile) {
		throw std::runtime_error("Error! Could not read server info from file. Terminating...\n");  //If unable- terminate program
	}
	std::getline(infile, line);
	size_t pos = line.find(':');
	if (pos != std::string::npos) {
		address = line.substr(0, pos);
		port = line.substr(pos + 1);
	}
	else {  //If unable- terminate program
		throw std::runtime_error("Invalid format in server info file. Terminating...\n");
	}
}

//Upon logging on, if user has a me.info file on their device, the users info (username,ID,private key) is read from that file
void read_info_from_file(const std::string& filepath, std::vector<uint8_t>& uuidVec, std::string& base64key, std::string& username) {
	std::ifstream file(filepath);
	if (!file.is_open()) {
		throw std::runtime_error("User info error. Failed to open user info file.");
	}

	std::string line;
	if (!std::getline(file, username)) {	// Read the first line (username)
		std::cerr << "Failed to read username from file";
		throw std::runtime_error("User info error. Failed to read username from file\n");
	}

	if (!std::getline(file, line)) {	// Read the second line (UUID)
		throw std::runtime_error("User info error. Failed to read the UUID from file.\n");
	}

	if (line.size() != 32) {		// Ensure the UUID has exactly 32 hex characters
		throw std::runtime_error("User info error. Invalid UUID format (length).\n");
	}

	for (char ch : line) {
		if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F'))) {	// Not a valid hex character
			throw std::runtime_error("User info error. Invalid UUID format (non hexa chars detected).\n");
		}
	}

	std::stringstream buffer;	// Obtain the base64 private key for the existing user
	buffer << file.rdbuf();

	base64key = buffer.str();  // Convert to string

	uuidVec.clear();		// Parse the UUID string and store it in the vector as bytes, used by client
	for (size_t i = 0; i < line.size(); i += 2) {
		uint8_t byte = std::stoi(line.substr(i, 2), nullptr, 16);
		uuidVec.push_back(byte);
	}
	return;
}

//Function for signing up. Receives username from user, validates it (or not), and sends signup request to server.
void signup(tcp::socket& s, std::string& username, std::string& hex_uuid, std::vector<uint8_t>& UUID_buffer, std::string& public_key) {
	std::vector<uint8_t> vec(16, 0);
	std::array<uint8_t, 255>username_buffer = {};

	std::cout << "Please choose a username-\n ";
	std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
	bool validity = false;
	while (!validity) {
		std::getline(std::cin, username);
		username = trim(username);			//Remove whitespaces
		if (username.length() > 254)		//Cant be too long
			std::cout << "Error in choosing username. Username too long. Please choose a username less than 254 characters long.\n";
		else if (username == "")   //Or only whitespace
			std::cout << "Error in choosing username. Username cannot be only empty space. It must contain letters. Please choose a valid username.\n";
		else
			validity = true;
	}

	std::memcpy(username_buffer.data(), username.c_str(), username.length());
	std::vector<uint8_t>buffer = build_request_header(vec, 2, 600, 415);  //Request header containing the neccessary data

	buffer.insert(buffer.end(), username_buffer.begin(), username_buffer.end());
	buffer.insert(buffer.end(), public_key.begin(), public_key.end());
	try {
		boost::asio::write(s, boost::asio::buffer(buffer));  //Send header, username, and public key, to the server
	}
	catch (std::exception&) {
		throw std::runtime_error("Error. Coundn't complete request\n");
	}

	char buff[7];
	try {
		boost::asio::read(s, boost::asio::buffer(buff, 7));  //Read response header
	}
	catch (std::exception&) {
		throw std::runtime_error("Error. Coundn't receive server response\n");
	}
	uint8_t serv_version = buff[0];
	uint16_t serv_opcode;				//Parse the response header. Little endian format
	uint32_t serv_payload_size;
	serv_opcode = boost::endian::load_little_u16(reinterpret_cast<const unsigned char*>(buff + 1));
	serv_payload_size = boost::endian::load_little_u32(reinterpret_cast<const unsigned char*>(buff + 3));
	
	if (serv_opcode == 2100) {  //Successful signup. Return to main, to store the user data
		UUID_buffer.resize(serv_payload_size);
		boost::asio::read(s, boost::asio::buffer(UUID_buffer, serv_payload_size));  //Receive user ID (UUID) from server
		std::ostringstream oss;
		oss << std::hex << std::setfill('0');  
		for (uint8_t byte : UUID_buffer)		//Store a hexa version of the UUID as well, for saving in the file
			oss << std::setw(2) << (int)byte;
		hex_uuid = oss.str();
		return;
	}

	else if (serv_opcode == 9000) {   //Server error (possibly because the username chosen is already in use)
		throw std::runtime_error("Server responded with an error");
	}

	else { //Error processing response
		throw std::runtime_error("Error. Couldnt process server response\n");
	}
}

//This function saves all the newly signed-up clients info in the file.
void create_client_info_file(const std::string& filepath, const std::string& username, const std::string& hex_uuid, const std::string& private_key) {
	std::ofstream file(filepath);
	if (file) {
		file << username << "\n";		//Save the username, UUID in hex format, and users private key
		file << hex_uuid << "\n";
		file << private_key;
	}
	else {  //If couldnt save, throw an error and wait for next request
		throw std::runtime_error("Error in creating contact file. Cannot create contact right now. Please try again later.\n");
	}

}