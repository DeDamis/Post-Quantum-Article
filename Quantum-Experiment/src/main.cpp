#include <Arduino.h>
#include "config.hpp"
#include "credentials.hpp"
#include "ML_DSA_PublicKey.hpp"

#ifdef __cplusplus
extern "C" {
#endif
#include "api.h"  // PQCLEAN_MLDSA65_CLEAN_* function declarations
#ifdef __cplusplus
}
#endif

// hard-coded server’s IP address and port
const char *serverIP = "192.168.50.44"; // Example IP
const uint16_t serverPort = 8080;       // Example port

// Create a global WiFiClient object to manage the TCP connection
WiFiClient client;

void setup() {
  Serial.begin(9600); // Start serial for debug output
  delay(200);         // Let the serial line settle
  Serial.println("Booting up...");

  // Try to connect to Wi-Fi
  //wifiConnection = establishWifiConnection();

  uint8_t pk[PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES];

  /*
  if (PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair(pk, sk) == 0) {
    Serial.println("Keys generated.");
  }
  */

}

void loop() {
  // Periodically report status
  if (millis() > (report_delay + 2000)) {
    Serial.println("Running..");
    report_delay = millis();
  }

  // If Wi-Fi is connected, check if we can connect to the server
  // (Optionally, you can wrap this in a condition so it only attempts once or on demand.)
  if (millis() > (tcp_delay + 10000)) {
    if (wifiConnection && !client.connected()) {
      connectToServer();
    }
    tcp_delay = millis();
  }

  if (!wifiConnection) { // Kontrola připojení Wifi. Pokud není připojení aktivní, dojde ke kontrole aktuálního stavu
    if (WiFi.status() == WL_CONNECTED){
      wifiConnection = true; // Stav Wifi připojení se změní na funkční
      getWifiInfo();         // Funkce vypíše informace o Wifi připojení
    }
    if(!wifiConnection && (millis() > WiFi_retry_delay + 10000)){
      wifiConnection = establishWifiConnection();
      //listAvailableNetworks();
      WiFi_retry_delay = millis();
      Serial.println(WiFi.status());
    }
  }
}

bool connectToServer() {
  Serial.println();
  Serial.print("Attempting TCP connection to ");
  Serial.print(serverIP);
  Serial.print(":");
  Serial.println(serverPort);

  // Attempt to connect
  if (!client.connect(serverIP, serverPort)) {
    Serial.println("TCP connection failed.");
    return false;
  }

  Serial.println("TCP connection successful!");

  // Send message to server
  client.println("AuthRequest");
  delay(1000);
  while (client.available()) {
    char c = client.read();
    Serial.write(c);
   }
  Serial.println();
  client.println("Ack.");
  return true;
}

bool establishWifiConnection() {
  Serial.println();
  Serial.println();
  Serial.print("Connecting to ");
  Serial.println(ssid);
  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid, password);
  if (WiFi.status() == WL_CONNECTED) {
    getWifiInfo();
    return true;
  }
  else {
    Serial.println("");
    Serial.println("Couldn't establish Wifi connection at the moment.");
    return false;
  }
}

void getWifiInfo(){
  Serial.println("");
  Serial.println("WiFi connected");
  Serial.print("IP address:  ");
  Serial.println(WiFi.localIP());
  Serial.println("");
}


void listAvailableNetworks() {
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
