#include "config.hpp"
#include "WifiManagement.hpp"
#include "ML_DSA_PublicKey.hpp"

// hard-coded server’s IP address and port
const char *serverIP = "192.168.50.44"; // Example IP
const uint16_t serverPort = 8080;       // Example port

void setup() {
  Serial.begin(9600); // Start serial for debug output
  delay(200);         // Let the serial line settle
  Serial.println("Booting up...");

  // Try to connect to Wi-Fi
  //wifiConnection = establishWifiConnection();

  uint8_t pk[PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES];

  
  if (PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair(pk, sk) == 0) {
    Serial.println("Keys generated.");
  }
  

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