#pragma once
#include <iostream>      
#include <fstream>      
#include <sstream>      
#include <vector>
#include <array>
#include <string>
#include <stdexcept>
#include <iomanip>
#include <limits>
#include <cstring>
#include <boost/asio.hpp>
#include <boost/endian/conversion.hpp>

using boost::asio::ip::tcp;
std::vector<uint8_t> build_request_header(std::vector<uint8_t>ID, uint8_t version, uint16_t code, uint32_t payload_size);
std::string trim(const std::string& str);