#include "Utils.hpp"

namespace Utils {

// ── hexToBytes ─────────────────────────────────────────────────────
/**
 * @brief Convert a hex string to bytes.
 * @param hex       Input hex (length == expectedLen*2).
 * @param out       Output buffer.
 * @param expectedLen  Number of bytes expected.
 * @return true if successful.
 */
bool hexToBytes(const char* hex, uint8_t* out, size_t expectedLen)
{
    size_t hexLen = strlen(hex);
    if (hexLen != expectedLen * 2)
        return false;
    for (size_t i = 0; i < expectedLen; ++i) {
        char buf[3] = { hex[2 * i], hex[2 * i + 1], '\0' };
        out[i] = (uint8_t)strtoul(buf, nullptr, 16);
    }
    return true;
}

// ── bytesToHex ─────────────────────────────────────────────────────
/**
 * @brief Convert bytes to uppercase hex string.
 * @param in       Input bytes.
 * @param len      Number of bytes.
 * @param out      Output buffer (size >= len*2+1).
 */
bool bytesToHex(const uint8_t* in, size_t len, char* out, size_t outSize)
{
    if (outSize < (len * 2 + 1))
        return false;
    static const char hexChars[] = "0123456789ABCDEF";
    for (size_t i = 0; i < len; ++i) {
        out[2 * i] = hexChars[in[i] >> 4];
        out[2 * i + 1] = hexChars[in[i] & 0x0F];
    }
    out[len * 2] = '\0';
    return true;
}

// ── establishWifiConnection ─────────────────────────────────────────
/** Connect to Wi‑Fi once; returns connected status. */
bool establishWifiConnection(const char* ssid, const char* password)
{
    Serial.println();
    Serial.print(F("Connecting to "));
    Serial.println(ssid);
    WiFi.mode(WIFI_STA);
    WiFi.begin(ssid, password);
    delay(50);
    if (WiFi.status() == WL_CONNECTED) {
        getWifiInfo();
        return true;
    }
    Serial.println(F("Unable to connect to Wi‑Fi right now."));
    return false;
}

// ── getWifiInfo ─────────────────────────────────────────────────────
/** Print IP and link status over Serial. */
void getWifiInfo()
{
    Serial.println(F("\nWiFi connected"));
    Serial.print(F("IP address: "));
    Serial.println(WiFi.localIP());
    Serial.println();
}

// ── listAvailableNetworks ───────────────────────────────────────────
/** Scan for and list available SSIDs. */
void listAvailableNetworks()
{
    Serial.println(F("Scanning for networks..."));
    int n = WiFi.scanNetworks();
    if (n == 0) {
        Serial.println(F("No networks found."));
    } else {
        Serial.printf("%d networks found:\n", n);
        for (int i = 0; i < n; ++i) {
            Serial.printf("%d: %s (RSSI %d dBm)%s\n",
                i + 1,
                WiFi.SSID(i).c_str(),
                WiFi.RSSI(i),
                (WiFi.encryptionType(i) == ENC_TYPE_NONE) ? " [Open]" : " [Encrypted]");
            delay(10);
        }
    }
    WiFi.scanDelete();
    Serial.println();
}

} // namespace Utils
