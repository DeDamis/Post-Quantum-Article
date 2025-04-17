#include "WifiManagement.hpp"
#include "credentials.hpp"

bool establishWifiConnection()
{
    Serial.println();
    Serial.println();
    Serial.print("Connecting to ");
    Serial.println(ssid);
    WiFi.mode(WIFI_STA);
    WiFi.begin(ssid, password);
    delay(50); // Could be removed
    if (WiFi.status() == WL_CONNECTED) {
        getWifiInfo();
        return true;
    } else {
        Serial.println("");
        Serial.println("Couldn't establish Wifi connection at the moment.");
        return false;
    }
}

void getWifiInfo()
{
    Serial.println("");
    Serial.println("WiFi connected");
    Serial.print("IP address:  ");
    Serial.println(WiFi.localIP());
    Serial.println("");
}

void listAvailableNetworks()
{
    Serial.println("Scanning for available networks...");

    // Initiate a Wi-Fi scan
    int numNetworks = WiFi.scanNetworks();
    if (numNetworks == 0) {
        Serial.println("No networks found.");
    } else {
        Serial.print(numNetworks);
        Serial.println(" network(s) found:");
        for (int i = 0; i < numNetworks; i++) {
            // Print SSID and signal strength
            Serial.printf("%d: %s (RSSI: %d dBm)",
                i + 1,
                WiFi.SSID(i).c_str(),
                WiFi.RSSI(i));

            // Identify if network is encrypted
            auto encryptionType = WiFi.encryptionType(i);
            if (encryptionType == ENC_TYPE_NONE) {
                Serial.println(" [Open]");
            } else {
                Serial.println(" [Encrypted]");
            }

            delay(10);
        }
    }
    Serial.println();
    // Optionally, clear the scan results to free memory
    WiFi.scanDelete();
}
