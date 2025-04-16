#include "helpers.hpp"

// Helper: Convert a hex string (C-string) to binary.
// The hex string must be exactly expectedLen*2 characters long.
bool hexToBytes(const char* hex, uint8_t* out, size_t expectedLen)
{
    size_t hexLen = strlen(hex);
    if (hexLen != expectedLen * 2)
        return false;
    for (size_t i = 0; i < expectedLen; i++) {
        char hexPair[3] = { hex[2 * i], hex[2 * i + 1], '\0' };
        out[i] = (uint8_t)strtoul(hexPair, NULL, 16);
    }
    return true;
}