#include <Arduino.h>

bool hexToBytes(const char* hex, uint8_t* out, size_t expectedLen);

bool bytesToHex(const uint8_t* in, size_t len, char* out, size_t outSize);