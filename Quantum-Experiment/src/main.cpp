#include "ML_DSA_PublicKey.hpp"
#include "WifiManagement.hpp"
#include "config.hpp"
#include "helpers.hpp"

// hard-coded server’s IP address and port
const char* serverIP = "192.168.50.44"; // Example IP
const uint16_t serverPort = 8080; // Example port

void setup()
{
    Serial.begin(9600); // Start serial for debug output
    delay(200); // Let the serial line settle
    Serial.println("Booting up...");

    // Try to connect to Wi-Fi
    // wifiConnection = establishWifiConnection();

    /*
    char* publicKeyBuffer = (char*) malloc((PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES * 2 + 1)*sizeof(char));
    strcpy_P(publicKeyBuffer, dilithiumPublicKey);
    Serial.println("Server' Public Key:");
    Serial.println(publicKeyBuffer);
    Serial.println();
    free(publicKeyBuffer);
    */
}

void loop()
{
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
        if (WiFi.status() == WL_CONNECTED) {
            wifiConnection = true; // Stav Wifi připojení se změní na funkční
            getWifiInfo(); // Funkce vypíše informace o Wifi připojení
        }
        if (!wifiConnection && (millis() > WiFi_retry_delay + 10000)) {
            wifiConnection = establishWifiConnection();
            // listAvailableNetworks();
            WiFi_retry_delay = millis();
            Serial.println(WiFi.status());
        }
    }
}

bool connectToServer()
{
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
    // Receive a message in a format of
    // AuthReply:[UNIX timestamp]|signature:[ML-DSA-Signature]
    String response;
    unsigned long start = millis();
    while ((millis() - start) < 10000) { // 5 second timeout
        while (client.available()) {
            char c = client.read();
            response += c;
            start = millis(); // reset timeout when data is coming in
        }
    }
    Serial.println(response);
    if (response.length() > 1) {
        client.println("Ack");
        processAuthReply(response);
    } else {
        Serial.println("Response error.");
    }
    return true;
}

// Example usage in your code:
void processAuthReply(String reply)
{
    String control;
    unsigned long timestamp;
    String sig;

    parseAuthReply(reply, control, timestamp, sig);

    Serial.println("Parsed Values:");
    Serial.print("Control word: ");
    Serial.println(control);
    Serial.print("UNIX timestamp: ");
    Serial.println(timestamp);
    Serial.print("Signature: ");
    Serial.println(sig);
    verifyAuthReply(control, timestamp, sig);
}

// Function to parse the AuthReply message into three variables.
// The expected message format is:
// "AuthReply:1744750583|signature:5D5056F7BEB494287A396EEA50E2CFDA..."
void parseAuthReply(const String& reply, String& controlWord, unsigned long& unixStamp, String& signature)
{
    // Find the first colon: separates the control word from the timestamp.
    int colonIndex = reply.indexOf(':');
    if (colonIndex == -1) {
        Serial.println("Error: colon not found.");
        return;
    }
    // Extract the control word (e.g. "AuthReply")
    controlWord = reply.substring(0, colonIndex);

    // Find the pipe character that separates the timestamp from the signature.
    int pipeIndex = reply.indexOf('|');
    if (pipeIndex == -1) {
        Serial.println("Error: pipe character not found.");
        return;
    }
    // Extract timestamp string from after the colon to the pipe
    String timestampStr = reply.substring(colonIndex + 1, pipeIndex);
    unixStamp = timestampStr.toInt(); // Convert to numeric value

    // Now find the colon that comes after "signature"
    int secondColon = reply.indexOf(':', pipeIndex);
    if (secondColon == -1) {
        Serial.println("Error: second colon not found.");
        return;
    }
    // Extract signature (everything after the second colon)
    signature = reply.substring(secondColon + 1);
}

bool verifyAuthReply(const String& controlWord, unsigned long timestamp, const String& signatureHex)
{
    if (controlWord != "AuthReply") {
        Serial.println("Control word mismatch.");
        return false;
    }

    // Construct the message string: "AuthReply:<timestamp>"
    String message = "AuthReply:" + String(timestamp);
    const uint8_t* msg = reinterpret_cast<const uint8_t*>(message.c_str());
    size_t msgLen = message.length();

    Serial.print("Expected signature length: ");
    Serial.println(PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES * 2);
    Serial.print("Actual signature length: ");
    Serial.println(signatureHex.length());

    // Decode signature from hex string
    static uint8_t sig[PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES];
    if (!hexToBytes(signatureHex, sig, PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES)) {
        Serial.println("Signature hex decode failed.");
        return false;
    }
    Serial.println("Signature hex decode OK.");

    char* pkHex = (char*)malloc((PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES * 2 + 1) * sizeof(char));
    strcpy_P(pkHex, dilithiumPublicKey);

    static uint8_t pk[PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES];
    if (!hexToBytes(String(pkHex), pk, PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES)) {
        Serial.println("Public key hex decode failed.");
        return false;
    }
    Serial.println("Public Key hex decode OK.");

    // Verify the signature
    int ret = 1; // PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify(sig, sizeof(sig), msg, msgLen, pk);
    if (ret == 0) {
        Serial.println("Signature is VALID.");
        return true;
    } else {
        Serial.println("Signature is INVALID.");
        return false;
    }

    free(pkHex);
}