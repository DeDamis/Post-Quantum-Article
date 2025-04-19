#ifndef UTILS_HPP
#define UTILS_HPP

#include <Arduino.h>
#include <ESP8266WiFi.h>
#include <cstring> // for strlen, strtoul

/* Error if both KEM and AUTH are enabled */
#if defined(KEM) && defined(AUTH)
#error "Both KEM and AUTH (Digital Signature) won't fit within the board's RAM"
#endif

/* Error if AES is enabled without KEM */
#if defined(AES) && !defined(KEM)
#error "AES won't work without KEM."
#endif

namespace Utils {

// ── Hex/binary conversion ──────────────────────────────────────────

// Convert a hex‑string (must be exactly expectedLen*2 chars) into bytes.
// Returns true on success, false on length or parse error.
bool hexToBytes(const char* hex, uint8_t* out, size_t expectedLen);

// Convert a byte‑array into an uppercase hex‑string (outSize >= len*2+1).
// Returns true on success, false if outSize is too small.
bool bytesToHex(const uint8_t* in, size_t len, char* out, size_t outSize);

// ── Wi‑Fi management ────────────────────────────────────────────────

// Attempts to connect to the network defined in credentials.hpp.
// Returns true if already or now connected, false on failure.
bool establishWifiConnection(const char* ssid, const char* password);

// Prints IP address and other info to Serial (upon successful connect).
void getWifiInfo();

// Scans and dumps all available SSIDs + RSSI to Serial.
void listAvailableNetworks();

} // namespace Utils

#endif // UTILS_HPP
