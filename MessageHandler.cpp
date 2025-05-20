#include "Includes.h"
#include <ctime>
#include <cstdlib>
std::string generateRandomString(size_t length);

void send_message_to_client(tcp::socket& s, const std::vector<uint8_t>& UUID, uint8_t message_type, const std::array<uint8_t, 16>& ID_For_Receiver, std::string symmkeyORpubkey, std::string Name_For_Receiver, std::unordered_map<std::string, std::string>& NameSymmKeyMap) {

	std::string client_message;
	std::string cipher_message;
	std::string ciphertext;
	uint32_t payload_size;
	uint32_t content_size = 0;

	if (message_type == 1) {	//Sending request for symmetric key- no more content
		content_size = 0;
	}
	else if (message_type == 2) { //Sending a symmetric key. Encrypting it with receivers public key.
		try {
			unsigned char key[AESWrapper::DEFAULT_KEYLENGTH];
			AESWrapper aes(AESWrapper::GenerateKey(key, AESWrapper::DEFAULT_KEYLENGTH), AESWrapper::DEFAULT_KEYLENGTH);
			std::string symm_key_string(reinterpret_cast<const char*>(key), sizeof(key));
			NameSymmKeyMap[Name_For_Receiver] = symm_key_string;  //Save symmetric key for this user
			RSAPublicWrapper rsapub(symmkeyORpubkey);
			cipher_message = rsapub.encrypt(reinterpret_cast<const char*>(key), sizeof(key));  //Encrypt the key (with receivers public key) to send to user
			content_size = static_cast<uint32_t>(cipher_message.length());
		}
		catch (const std::exception&) {
			throw std::runtime_error("Error in creating and encrypting symmetric key. Clients public key may be corrupted, or the symmetric key may be corrupted\n");
		}
	}
	else if (message_type == 3) {  //Sending a text message. Receives the message, and encrypts it with symmetric key user shares with the receiver 
		std::cout << "Please enter the message you would like to send:\n";
		std::getline(std::cin, client_message);
		try {
			AESWrapper aes2(reinterpret_cast<unsigned char*>(symmkeyORpubkey.data()), static_cast<unsigned int>(symmkeyORpubkey.size()));  //Creating an encryptor with the symmetric key
			while (client_message.length() > UINT32_MAX) {
				std::cerr << "Message is too long\nPlease enter a valid message\n";
				std::getline(std::cin, client_message);
			}
			cipher_message = aes2.encrypt(client_message.c_str(), static_cast<unsigned int>(client_message.length()));  //Encrypting the text message
			content_size = static_cast<uint32_t>(cipher_message.length());
		}
		catch (std::exception&) {
			throw std::runtime_error("Error in creating symmetric key and encrypting the message. The symmetric key may be corrupted\n");
		}
	}
	else if (message_type == 4) {  //User is sending a file
		std::string filepath;
		std::vector<char>file_content;
		std::cout << "Please enter the complete filepath of the file you would like to send\n";
		std::getline(std::cin, filepath);
		if (!std::filesystem::exists(filepath)) {  //Gets the filepath and validates it is a valid location. If not, throws an error and proceeds to next request
			throw std::runtime_error("Error in reading file. File does not exist, or filepath may be incorrect.\n");
		}
		try {
			std::ifstream file(filepath, std::ios::binary);  //Reads file content
			file_content.insert(file_content.begin(),std::istreambuf_iterator<char>(file),std::istreambuf_iterator<char>());
		}
		catch (std::exception&) {
			throw std::runtime_error("Error in reading file data. Could not get file data to send\n");
		}
		if (file_content.size() > UINT32_MAX-15) {
			throw std::runtime_error("File content is too large\nPlease choose a different operation\n");
		}
		try {
			AESWrapper aes2(reinterpret_cast<unsigned char*>(symmkeyORpubkey.data()), static_cast<unsigned int>(symmkeyORpubkey.size()));  //Create an encryptor using the symmetric key
			cipher_message = aes2.encrypt(file_content.data(), static_cast<unsigned int>(file_content.size()));  //Encrypts file content
			content_size = static_cast<uint32_t>(cipher_message.size());
		}
		catch (std::exception&) {
			throw std::runtime_error("Error in creating symmetric key and encrypting the file content.The symmetric key may be corrupted\n");
		}
	}

	payload_size = 21 + content_size;  //Payload size is header + content itself

	std::vector<uint8_t>buffer = build_request_header(UUID, 2, 603, payload_size);  //Building the request header with opcode ID and payload size

	buffer.insert(buffer.end(), ID_For_Receiver.begin(), ID_For_Receiver.end());
	buffer.push_back(message_type);
	buffer.push_back(content_size & 0xFF);
	buffer.push_back((content_size >> 8) & 0xFF);		//Build message format- all little endian
	buffer.push_back((content_size >> 16) & 0xFF);
	buffer.push_back((content_size >> 24) & 0xFF);
	if (message_type == 3 || message_type == 2 || message_type==4) {
		buffer.insert(buffer.end(), cipher_message.begin(), cipher_message.end());  //If there is content to the message, it is appended
	}

	try {
		boost::asio::write(s, boost::asio::buffer(buffer));  //Sending request
	}
	catch (const std::exception&) {
		throw std::runtime_error("Error. Couldnt complete request\n");
	}

	char buff[7];
	try {
		boost::asio::read(s, boost::asio::buffer(buff, 7));  //Receiving response header. All little endian format
	}
	catch (const std::exception&) {
		throw std::runtime_error("Error. Coundn't receive server response\n");
	}
	uint8_t serv_version = buff[0];
	uint16_t serv_opcode;
	uint32_t serv_payload_size;
	serv_opcode = boost::endian::load_little_u16(reinterpret_cast<const unsigned char*>(buff + 1));
	serv_payload_size = boost::endian::load_little_u32(reinterpret_cast<const unsigned char*>(buff + 3));
	if (serv_opcode == 9000) {  //Error on server-side
		throw std::runtime_error("Server responded with an error\n");
	}
	else if (serv_opcode != 2103) {  //Error in response
		throw std::runtime_error("Error in processing server response\n");
	}
	std::vector<uint8_t>Receiver_ID_and_MessageID(serv_payload_size);
	try {
		boost::asio::read(s, boost::asio::buffer(Receiver_ID_and_MessageID.data(), serv_payload_size));  //Receiving acknowledgment
	}
	catch (const std::exception&) {
		throw std::runtime_error("Error. Couldnt receive server response\n");
	}
	std::cout << "Message sent to "<< Name_For_Receiver <<"\n\n";
	return;
}

void get_messages(tcp::socket& s, const std::vector<uint8_t>& UUID, std::map<std::array<uint8_t, 16>, std::string>& ID_Name_Pair, std::string& base64key, std::unordered_map<std::string, bool>& NameSymkeyStatus, std::unordered_map<std::string, std::string>& NameSymmKeyMap) {

	std::vector<uint8_t>buffer = build_request_header(UUID, 2, 604, 0);  //Header for request to pull messages
	try {
		boost::asio::write(s, boost::asio::buffer(buffer));  //Sending request
	}
	catch (const std::exception&) {
		throw std::runtime_error("Error. Coundn't complete request\n");
	}
	char buff[7];
	try {
		boost::asio::read(s, boost::asio::buffer(buff, 7));  //Receiving response header. All little endian format
	}
	catch (const std::exception&) {
		throw std::runtime_error("Error. Coundn't receive server response\n");
	}
	uint8_t serv_version = buff[0];
	uint16_t serv_opcode;
	uint32_t serv_payload_size;
	serv_opcode = boost::endian::load_little_u16(reinterpret_cast<const unsigned char*>(buff + 1));
	serv_payload_size = boost::endian::load_little_u32(reinterpret_cast<const unsigned char*>(buff + 3));
	std::size_t total_bytes_read = 0;
	std::size_t bytes_read;
	if (serv_opcode == 9000) {  //Erro on server side
		throw std::runtime_error("Server responded with an error\n");
	}
	else if (serv_opcode != 2104) {  //Error in response
		throw std::runtime_error("Error in processing server response\n");
	}
	if (serv_payload_size == 0) {  //No payload = no messages
		std::cout << "You have no messages waiting for you\n";
		return;
	}
	while (total_bytes_read < serv_payload_size) {  //Read messages until read payload amount
		char message_header[25];  //Message header- contains sender ID, message type, message size.
		std::array<uint8_t, 16>sender_id;
		uint32_t message_id;
		uint8_t message_type;
		uint32_t message_size;
		try {
			bytes_read = boost::asio::read(s, boost::asio::buffer(message_header, 25));  //Receive message header
		}
		catch (const std::exception&) {
			throw std::runtime_error("Error. Coundn't receive server response\n");
		}
		total_bytes_read += bytes_read;		//Reads the message and tracks bytes read (to control iterations). All little endian format
		std::memcpy(sender_id.data(), message_header, 16);
		message_id = boost::endian::load_little_u32(reinterpret_cast<const unsigned char*>(message_header + 16));
		message_type = message_header[20];
		message_size = boost::endian::load_little_u32(reinterpret_cast<const unsigned char*>(message_header + 21));
		std::vector<uint8_t>message_content_vector(message_size);

		try {
			bytes_read = boost::asio::read(s, boost::asio::buffer(message_content_vector, message_size));  //Read message itself
		}
		catch (const std::exception&) {
			throw std::runtime_error("Error. Coundn't receive server response. Couldnt receive messages from server");
		}
		total_bytes_read += bytes_read;
		std::string sender_username;
		try {
			sender_username = ID_Name_Pair.at(sender_id);  //Extract username using ID-name map
		}
		catch (const std::out_of_range&) {  //Receiver didnt get this clients name yet- "Unknown user" is displayed
			sender_username = "Unknown user";
		}
		std::cout << "From: " << sender_username << std::endl;
		std::cout << "Content: \n";  //Different messages are displayed for each type of message
		if (message_type == 1)  //Requested key
			std::cout << "Request for symmetric key\n";
		if (message_type == 2) { //Received key
			std::cout << "Symmetric key received\n";
			std::string cipher_symm_key(message_content_vector.begin(), message_content_vector.end());
			try {
				RSAPrivateWrapper rsapriv_other(Base64Wrapper::decode(base64key));
				std::string decrypted = rsapriv_other.decrypt(cipher_symm_key);  //Decrypt the symmetric key sent
				NameSymkeyStatus[sender_username] = true;  //Update key status with other user
				NameSymmKeyMap[sender_username] = decrypted;  //Store the other users key
			}
			catch (const std::exception& e) {
				std::cerr << "Error in decrypting the symmetric key. Couldn't decrypt message. " << e.what() << "\n";
				continue;
			}
		}
		if (message_type == 3) {  //Received text message
			std::string cipher_message(message_content_vector.begin(), message_content_vector.end());
			std::string symmkey = NameSymmKeyMap[sender_username];  //Get symmetric key shared with user
			try {
				AESWrapper aes2(reinterpret_cast<unsigned char*>(symmkey.data()), static_cast<unsigned int>(symmkey.size()));
				std::string decrypted = aes2.decrypt(cipher_message.c_str(), static_cast<unsigned int>(cipher_message.length()));
				std::cout << decrypted << "\n";  //Decrypt the message using the key, and print it
			}
			catch (std::exception& e) {  //Key was lost (or logged out) or corrupted
				std::cerr << "Couldn't decrypt message. " << e.what() << "\n";
				continue;
			}
		}
		if (message_type == 4) {  //Received file
			std::string symmkey = NameSymmKeyMap[sender_username];  //Get symmetric key shared with other user
			std::string decrypted_data;
			try {
				AESWrapper aes2(reinterpret_cast<unsigned char*>(symmkey.data()), static_cast<unsigned int>(symmkey.size()));  //Decrypt file content
				decrypted_data = aes2.decrypt(reinterpret_cast<const char*>(message_content_vector.data()), static_cast<unsigned int>(message_content_vector.size()));
			}
			catch (std::exception& e) {  //Key was lost (or logged out) or corrupted
				std::cerr << "Couldn't decrypt message. " << e.what() << "\n";
				continue;
			}
			std::filesystem::path temp_path = std::filesystem::temp_directory_path();
			std::string filename = generateRandomString(10);
			std::filesystem::path file_path = temp_path / filename;  //Create file in %TMP% and create a random file name
			try {
				std::ofstream outfile(file_path);
				outfile << decrypted_data;  //Write the received file content to the newly created file
				outfile.close();
				std::cout << "File created to store received file data, at: " << file_path << std::endl;
			}
			catch (std::exception&) {
				throw std::runtime_error("Error. Could not write file content to new file\n");
			}
		}
		std::cout << "\n-----END OF MESSAGE-----\n\n";
	}
	std::cout << "No more messages to be displayed\n";
}

std::string generateRandomString(size_t length) {  //Generates a random string for the file name
	const std::string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	std::string randomStr;
	std::srand(static_cast<unsigned int>(std::time(0)));
	for (size_t i = 0; i < length; ++i) {
		randomStr += chars[std::rand() % chars.size()];
	}
	return randomStr;
}