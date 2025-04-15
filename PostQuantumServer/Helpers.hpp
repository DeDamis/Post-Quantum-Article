#ifndef HELPERS_HPP
#define HELPERS_HPP

#include <cstdint>   // for uint8_t
#include <string>

// Converts a byte array to a hex string
std::string bytesToHex(const uint8_t* data, size_t size);

// Converts a hex string to a byte array
bool hexToBytes(const std::string& hex, uint8_t* out, size_t outSize);

// Saves a key to file in hex-encoded form
bool saveKeyToFile(const std::string& filename, const uint8_t* key, size_t keySize);

// Loads a hex-encoded key from file into a byte array
bool loadKeyFromFile(const std::string& filename, uint8_t* key, size_t keySize);

#endif // HELPERS_HPP
