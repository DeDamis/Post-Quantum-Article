// Helpers.hpp
/**
 * @file Helpers.hpp
 * @brief Helper routines for hex‑encoding and file I/O of cryptographic keys.
 */

#ifndef HELPERS_HPP
#define HELPERS_HPP

#include <cstdint>   ///< for uint8_t
#include <string>    ///< for std::string

 /**
  * @brief Convert a byte array to its uppercase hexadecimal representation.
  * @param data Pointer to the input byte array.
  * @param size Number of bytes in the input array.
  * @return Uppercase hex string of length 2 * size.
  */
std::string bytesToHex(const uint8_t* data, size_t size);

/**
 * @brief Parse an uppercase hexadecimal string into a byte array.
 * @param hex   Hex string of length exactly 2 * outSize.
 * @param out   Output buffer for the parsed bytes.
 * @param outSize Expected number of bytes to write into out.
 * @return True if parsing succeeds; false on length mismatch or invalid chars.
 */
bool hexToBytes(const std::string& hex, uint8_t* out, size_t outSize);

/**
 * @brief Save a binary key to a file in hex‑encoded form.
 * @param filename Path to output file.
 * @param key      Pointer to the key bytes.
 * @param keySize  Number of bytes in the key.
 * @return True on successful write; false on I/O error.
 */
bool saveKeyToFile(const std::string& filename, const uint8_t* key, size_t keySize);

/**
 * @brief Load a hex‑encoded key from a file into a byte buffer.
 * @param filename Path to input file.
 * @param key      Output buffer for key bytes.
 * @param keySize  Number of bytes expected.
 * @return True on successful read and parse; false otherwise.
 */
bool loadKeyFromFile(const std::string& filename, uint8_t* key, size_t keySize);

#endif // HELPERS_HPP
