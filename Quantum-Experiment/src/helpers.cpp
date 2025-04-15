#include "helpers.hpp"

// Converts a hex string (2 characters per byte) into a byte array
bool hexToBytes(const String &hex, uint8_t *out, size_t expectedLen) {
    if (hex.length() != expectedLen * 2) return false;
  
    for (size_t i = 0; i < expectedLen; ++i) {
      char highChar = hex[2 * i];
      char lowChar  = hex[2 * i + 1];
      char hexPair[3] = {highChar, lowChar, '\0'};
      out[i] = strtoul(hexPair, nullptr, 16);
    }
  
    return true;
  }