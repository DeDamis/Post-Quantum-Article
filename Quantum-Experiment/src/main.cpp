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
    Serial.println(F("Booting up..."));

    // Try to connect to Wi-Fi
    // wifiConnection = establishWifiConnection();

    /*
    char* publicKeyBuffer = (char*) malloc((PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES * 2 + 1)*sizeof(char));
    strcpy_P(publicKeyBuffer, dilithiumPublicKey);
    Serial.println(F("Server' Public Key:");
    Serial.println(publicKeyBuffer);
    Serial.println();
    free(publicKeyBuffer);
    */
    Serial.print("Free heap: ");
    Serial.println(ESP.getFreeHeap());
}

void loop()
{
    // Periodically report status
    if (millis() > (report_delay + 2000)) {
        Serial.println(F("Running.."));
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
    Serial.print(F("Attempting TCP connection to "));
    Serial.print(serverIP);
    Serial.print(F(":"));
    Serial.println(serverPort);

    // Attempt to connect
    if (!client.connect(serverIP, serverPort)) {
        Serial.println(F("TCP connection failed."));
        return false;
    }

    Serial.println(F("TCP connection successful!"));

    // Send message to server
    client.println("AuthRequest");
    delay(1000);

    // Receive a message in a format of
    // AuthReply:[UNIX timestamp]|signature:[ML-DSA-Signature]

    // Allocate a response buffer from the heap.
    size_t bufferSize = 7000; // Adjust if necessary
    char* response = (char*)malloc(bufferSize);
    if (!response) {
        Serial.println(F("Failed to allocate memory for response."));
        return false;
    }
    size_t index = 0;
    unsigned long start = millis();

    // Read data from the server with a 10-second timeout.
    while ((millis() - start) < 10000) {
        while (client.available()) {
            char c = client.read();
            Serial.print(c); // Optional: echo data
            if (index < (bufferSize - 1)) { // leave room for null terminator
                response[index++] = c;
            }
            start = millis(); // Reset timeout
        }
    }
    response[index] = '\0'; // Null-terminate the received response

    Serial.println(); // Newline for clarity
    // Serial.println(response); // Debug print complete response

    if (index > 1) {
        Serial.println(F("Response OK."));
        client.println("Ack");
        processAuthReply(response);
    } else {
        Serial.println(F("Response error."));
    }
    free(response);
    return true;
}

//
// processAuthReply: parse the raw response (which uses no extra copies)
// Expected response format (in the same buffer):
// "AuthReply:<timestamp>|signature:<hexsignature>"
// Parsing is done in place by replacing delimiters with '\0'
//
bool processAuthReply(char* reply)
{
    // Find the first colon. It separates the control word from the timestamp.
    char* colon1 = strchr(reply, ':');
    if (!colon1) {
        Serial.println(F("Error: first colon not found."));
        free(reply);
        return false;
    }
    *colon1 = '\0';
    char* control = reply; // should be "AuthReply"

    // The rest should contain the timestamp followed by a pipe.
    char* rest = colon1 + 1;
    char* pipePos = strchr(rest, '|');
    if (!pipePos) {
        Serial.println(F("Error: pipe not found."));
        free(reply);
        return false;
    }
    *pipePos = '\0';
    char* timestampStr = rest;
    // Expect the "signature:" label after the pipe.
    const char* sigLabel = "signature:";
    char* signatureStart = strstr(pipePos + 1, sigLabel);
    if (!signatureStart) {
        Serial.println(F("Error: signature label not found."));
        free(reply);
        return false;
    }
    signatureStart += strlen(sigLabel); // Move pointer to start of hex signature

    // Debug print parsed values.
    // Serial.println(F("Parsed Values:");
    Serial.println(F("Parsed Values:"));
    Serial.println(F("Control word: "));
    Serial.println(control);
    Serial.println(F("Timestamp: "));
    Serial.println(timestampStr);
    Serial.println(F("Signature: "));
    Serial.println(signatureStart);

    // Construct the original message that was signed:
    // "AuthReply:<timestamp>"
    static char message[100]; // Should be plenty; adjust if needed.
    snprintf(message, sizeof(message), "%s:%s", control, timestampStr);
    Serial.print(F("Message for verification: "));
    Serial.println(message);

    // Get the public key from PROGMEM (assumed to be defined in dilithiumPublicKey)
    char* pkHex = (char*)malloc(((PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES * 2) + 1) * sizeof(char));
    if (!pkHex) {
        Serial.println(F("Failed to allocate memory for pkHex."));
        return false;
    }
    strcpy_P(pkHex, dilithiumPublicKey);

    // Verify the signature.
    bool valid = verifyAuthReply(message, signatureStart, pkHex);
    if (valid) {
        Serial.println(F("Signature is VALID."));
    } else {
        Serial.println(F("Signature is INVALID."));
    }
    free(pkHex);
    free(reply);
    return true;
}

//
// Verify the signature given the message, signature (in hex)
// and the public key (in hex). Returns true if valid.
bool verifyAuthReply(const char* message, const char* signatureHex, const char* pkHex)
{
    size_t msgLen = strlen(message);
    size_t expectedSigHexLen = PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES * 2;
    if (strlen(signatureHex) != expectedSigHexLen) {
        Serial.print(F("Signature hex length mismatch. Expected: "));
        Serial.print(expectedSigHexLen);
        Serial.print(F(", got: "));
        Serial.println(strlen(signatureHex));
        return false;
    }

    uint8_t* sig = (uint8_t*)malloc((PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES) * sizeof(uint8_t));
    if (!sig) {
        Serial.println(F("Failed to allocate memory for sig."));
        return false;
    }

    if (!hexToBytes(signatureHex, sig, PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES)) {
        Serial.println(F("Signature hex decode failed."));
        return false;
    }

    uint8_t* pk = (uint8_t*)malloc((PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES) * sizeof(uint8_t));
    if (!pk) {
        Serial.println(F("Failed to allocate memory for pk."));
        return false;
    }

    if (!hexToBytes(pkHex, pk, PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES)) {
        Serial.println(F("Public key hex decode failed."));
        return false;
    }

    int ret = PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(sig, sizeof(sig), reinterpret_cast<const uint8_t*>(message), msgLen, pk);
    free(sig);
    free(pk);
    return (ret == 0);
}