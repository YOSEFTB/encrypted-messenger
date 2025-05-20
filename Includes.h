#pragma once
#include <string>
#include <iostream>
#include <sstream>
#include <filesystem>
#include <cstdint>
#include <cstring>
#include <vector>
#include <map>
#include <unordered_map>
#include <array>
#include <fstream>
#include <stdexcept>
#include "RSAWrapper.h"
#include "AESWrapper.h"
#include "Base64Wrapper.h"
#include <boost/asio.hpp>
#include <boost/endian/conversion.hpp>

using boost::asio::ip::tcp;
void send_message_to_client(tcp::socket& s, const std::vector<uint8_t>& UUID, uint8_t message_type, const std::array<uint8_t, 16>& ID_For_Receiver, std::string pubkey, std::string Name_For_Receiver, std::unordered_map<std::string, std::string>& NameSymmKeyMap);
void request_public_key(tcp::socket& s, const std::vector<uint8_t>& UUID, const std::array<uint8_t, 16>& ID_For_Pubkey, std::unordered_map<std::string, std::string>& NamePubkeyMap, std::string NameForPubkey, std::vector<uint8_t>& pubkey);
void get_messages(tcp::socket& s, const std::vector<uint8_t>& UUID, std::map<std::array<uint8_t, 16>, std::string>& ID_Name_Pair, std::string& base64key, std::unordered_map<std::string, bool>& NameSymkeyStatus, std::unordered_map<std::string, std::string>& NameSymmKeyMap);
void read_info_from_file(const std::string& filepath, std::vector<uint8_t>& uuidVec, std::string& base64key, std::string& username);
void get_clients_list(tcp::socket& s, const std::vector<uint8_t>& UUID, std::unordered_map<std::string, std::array<uint8_t, 16>>& Name_ID_Pair, std::map<std::array<uint8_t, 16>, std::string>& ID_Name_Pair, std::unordered_map <std::string, std::string>& NamePubkeyMap, std::unordered_map <std::string, bool>& NameSymkeyStatus);
void signup(tcp::socket& sock, std::string& username, std::string& hex_uuid, std::vector<uint8_t>& UUID, std::string& public_key);
void create_client_info_file(const std::string& filepath, const std::string& username, const std::string& hex_uuid, const std::string& private_key);
std::vector<uint8_t> build_request_header(std::vector<uint8_t>ID, uint8_t version, uint16_t code, uint32_t payload_size);
std::string trim(const std::string& str);