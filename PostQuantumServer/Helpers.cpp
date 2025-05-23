// Helpers.cpp
/**
 * @file Helpers.cpp
 * @brief Implementation of hex conversion and key file I/O helpers.
 */

#include "Helpers.hpp"
#include <fstream>   ///< for file streams
#include <cctype>    ///< for toupper

 /**
  * @brief Convert a single hex character to its integer value.
  * @param c Hex digit character ('0'�'9', 'A'�'F', 'a'�'f').
  * @return 0�15 on success, or -1 if c is not a valid hex digit.
  */
static int fromHexChar(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    c = static_cast<char>(toupper(c));
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

std::string bytesToHex(const uint8_t* data, size_t size) {
    static const char hexDigits[] = "0123456789ABCDEF";
    std::string result;
    result.reserve(size * 2);
    for (size_t i = 0; i < size; i++) {
        uint8_t byte = data[i];
        result.push_back(hexDigits[byte >> 4]);
        result.push_back(hexDigits[byte & 0x0F]);
    }
    return result;
}

bool hexToBytes(const std::string& hex, uint8_t* out, size_t outSize) {
    // The hex string must be exactly 2 * outSize characters
    if (hex.size() != outSize * 2) {
        return false;
    }
    for (size_t i = 0; i < outSize; i++) {
        int high = fromHexChar(hex[2 * i]);
        int low = fromHexChar(hex[2 * i + 1]);
        if (high < 0 || low < 0) {
            return false;
        }
        out[i] = static_cast<uint8_t>((high << 4) | low);
    }
    return true;
}

bool saveKeyToFile(const std::string& filename, const uint8_t* key, size_t keySize) {
    std::ofstream ofs(filename, std::ios::out);
    if (!ofs.good()) {
        return false;
    }
    ofs << bytesToHex(key, keySize);
    return true;
}

bool loadKeyFromFile(const std::string& filename, uint8_t* key, size_t keySize) {
    std::ifstream ifs(filename, std::ios::in);
    if (!ifs.good()) {
        return false;
    }
    std::string hexLine;
    if (!std::getline(ifs, hexLine)) {
        return false;
    }
    return hexToBytes(hexLine, key, keySize);
}
