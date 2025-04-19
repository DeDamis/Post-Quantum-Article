#include "main.hpp"
#include "Utils.hpp"
#include "user-config.hpp"

// ------- Uncomment one to enable feature ------- //
// #define KEM
// #define AES
#define AUTH

// Application entrypoint: initialize serial for debugging.
void setup()
{
    Serial.begin(115200); // Start serial for debug output
    delay(200); // Let the serial line settle
    Serial.println(F("Booting up..."));

    Serial.print(F("Free heap after startup: "));
    Serial.println(ESP.getFreeHeap());
}

/**
 * @brief Main loop:
 *  - Periodically report status
 *  - Maintain Wi-Fi connection
 *  - Trigger TCP handshake when appropriate
 */
void loop()
{
    // Report status every ~2 seconds
    if (millis() > (report_stamp + report_delay)) {
        Serial.println(F("Running.."));
        report_stamp = millis();
    }

    // Every ~10 seconds, if Wi-Fi is connected, initiate TCP handshake
    if (millis() > (tcp_stamp + tcp_delay)) {
        if (wifiConnection && !client.connected()) {
            connectToServer(); // Perform TCP and protocol exchange
        }
        tcp_stamp = millis();
    }

    // Ensure Wi-Fi remains connected; retry every ~10 seconds if not
    if (!wifiConnection) {
        if (WiFi.status() == WL_CONNECTED) {
            wifiConnection = true;
            Utils::getWifiInfo(); // Print IP and connection details
        } else if (millis() > WiFi_retry + WiFi_retry_delay) {
            wifiConnection = Utils::establishWifiConnection(ssid, password);
            WiFi_retry = millis();
        }
    }
}

/**
 * @brief Establish a TCP connection and perform handshake (Auth/KEM/AES).
 * @return true if handshake succeeds, false otherwise.
 */
bool connectToServer()
{
    Serial.print(F("Free heap before TCP: "));
    Serial.println(ESP.getFreeHeap());

    Serial.println();
    Serial.print(F("Attempting TCP connection to "));
    Serial.print(serverIP);
    Serial.print(F(":"));
    Serial.println(serverPort);

    // Attempt to connect to server
    if (!client.connect(serverIP, serverPort)) {
        Serial.println(F("TCP connection failed."));
        return false;
    }
    Serial.println(F("TCP connection successful!"));

    static char response[5000]; // Buffer for server replies

#ifdef AUTH
    // Send authentication request
    Serial.println(F("-> AuthRequest"));
    client.println("AuthRequest");
    delay(500);

    // Receive and verify auth reply: "AuthReply:<timestamp>|signature:<hex>"
    processResponse(response, bufferSize);
    checkResponseLength(response, PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES);

    if (processAuthReply(response)) {
        Serial.println(F("Signature valid, sending Ack"));
        client.println("Ack");
        delay(500);

        Serial.print(F("Heap after auth: "));
        Serial.println(ESP.getFreeHeap());
    } else {
        client.stop(500);
        return false;
    }
#endif // AUTH

#ifdef KEM
    // Request and process KEM encapsulation
    Serial.println(F("-> KemRequest"));
    client.println("KemRequest");
    delay(500);

    processResponse(response, bufferSize);
    processKem(response, bufferSize);

    Serial.println(F("-> Sending KemCipher"));
    client.println(response);
#endif // KEM

#ifdef AES
#warning "AES encryption not implemented."     // send an AES-encrypted message to server "Post-Quantum Cryptography is Awesome."
#endif

    // Close TCP connection
    Serial.println(F("Closing TCP connection."));
    client.stop(500);
    return true;
}

#ifdef KEM
/**
 * @brief Handle KEM encapsulation protocol.
 * @param message  Input buffer containing "KemInit:<hex pk>"
 * @param bufferSize  Size of the buffer
 * @return true if encapsulation succeeded
 */
bool processKem(char* message, size_t bufferSize)
{
    const char* prefix = "KemInit:";
    const size_t prefixLen = strlen(prefix);

    // 1) Verify prefix
    if (strncmp(message, prefix, prefixLen) != 0) {
        Serial.println(F("KEM: Invalid control word."));
        return false;
    }
    yield();

    // 2) Extract and validate public key hex length
    char* pkHex = message + prefixLen; // pointer to first hex digit
    size_t pkHexLen = strlen(pkHex);
    const size_t pkBytes = PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES;
    if (pkHexLen != pkBytes * 2) { // must be 800 × 2 = 1600 hex
        Serial.println(F("KEM: Public key length mismatch."));
        return false;
    }
    yield();

    // 3) Convert hex to raw public key
    static uint8_t pk[pkBytes];
    if (!Utils::hexToBytes(pkHex, pk, pkBytes)) {
        Serial.println(F("KEM: pk hex decode failed."));
        return false;
    }
    yield();

    // 4) Encapsulate to produce ciphertext and shared secret
    const size_t ctBytes = PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES;
    uint8_t ct[ctBytes];
    unsigned long t0 = millis();
    if (PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(ct, kem_shared_secret, pk) != 0) {
        Serial.println(F("KEM: encapsulation failed."));
        return false;
    }
    unsigned long dt = millis() - t0;
    Serial.printf("Encapsulation took %lums\n", dt);
    yield();

    // 5) Convert ciphertext to hex
    static char ctHex[ctBytes * 2 + 1]; // 1537 bytes
    if (!Utils::bytesToHex(ct, ctBytes, ctHex, sizeof(ctHex))) {
        Serial.println(F("KEM: bytesToHex failed"));
        return false;
    }
    yield();
    // 6) Build response "KemCipher:<hex ct>"
    const char* ctPrefix = "KemCipher:";
    size_t needed = strlen(ctPrefix) + strlen(ctHex) + 1;
    if (needed > bufferSize) { // guard overflow
        Serial.println(F("KEM: buffer too small"));
        return false;
    }
    strcpy(message, ctPrefix);
    strcat(message, ctHex);
    yield();

    Serial.println(F("KEM: encapsulation OK"));
    Serial.print(F("Shared‑secret first 8 bytes: "));
    for (int i = 0; i < 8; ++i) {
        if (kem_shared_secret[i] < 0x10)
            Serial.print('0');
        Serial.print(kem_shared_secret[i], HEX);
        yield();
    }
    Serial.println();
    return true;
}
#endif // KEM

#ifdef AUTH
/**
 * @brief Parse and validate auth reply in-place.
 * @param reply  Buffer containing "AuthReply:<timestamp>|signature:<hex>"
 * @return true if signature is valid
 */
bool processAuthReply(char* reply)
{
    // Split control word and timestamp
    char* colon1 = strchr(reply, ':');
    if (!colon1) {
        Serial.println(F("Auth: Missing colon."));
        return false;
    }
    *colon1 = '\0';
    char* control = reply; // "AuthReply"
    char* rest = colon1 + 1;

    // Split timestamp and signature label
    char* pipePos = strchr(rest, '|');
    if (!pipePos) {
        Serial.println(F("Auth: Missing pipe."));
        return false;
    }
    *pipePos = '\0';
    char* timestampStr = rest;
    const char* sigLabel = "signature:";
    char* sigHex = strstr(pipePos + 1, sigLabel);
    if (!sigHex) {
        Serial.println(F("Auth: Missing signature label."));
        return false;
    }
    sigHex += strlen(sigLabel);

    // Reconstruct message "AuthReply:<timestamp>"
    static char message[100];
    snprintf(message, sizeof(message), "%s:%s", control, timestampStr);

    // Load public key from flash and verify
    char* pkHex = (char*)malloc(((PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES * 2) + 1) * sizeof(char));
    if (!pkHex) {
        Serial.println(F("Auth: Failed to allocate memory for pkHex."));
        return false;
    }
    strcpy_P(pkHex, dilithiumPublicKey);

    // Verify the signature.
    bool valid = verifyAuthReply(message, sigHex, pkHex);
    free(pkHex);
    Serial.println(valid ? F("Auth: VALID.") : F("Auth: INVALID."));
    return valid;
}

/**
 * @brief Verify ML‑DSA signature over message.
 * @param message      Original message
 * @param signatureHex Signature in hex
 * @param pkHex        Public key in hex
 * @return true if signature valid
 */
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

    if (!Utils::hexToBytes(signatureHex, sig, PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES)) {
        Serial.println(F("Signature hex decode failed."));
        free(sig); // <— free on failure
        return false;
    }

    Serial.println(F("First 16 sig‑bytes (hex):"));
    for (int i = 0; i < 16; i++) {
        if (sig[i] < 16)
            Serial.print('0');
        Serial.print(sig[i], HEX);
    }
    Serial.println();

    uint8_t* pk = (uint8_t*)malloc((PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES) * sizeof(uint8_t));
    if (!pk) {
        Serial.println(F("Failed to allocate memory for pk."));
        free(sig); // <— free the sig too
        return false;
    }

    if (!Utils::hexToBytes(pkHex, pk, PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES)) {
        Serial.println(F("Public key hex decode failed."));
        free(sig);
        free(pk); // <— free both
        return false;
    }

    Serial.printf("pk bytes=%u sig bytes=%u\n", (unsigned)PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES, (unsigned)PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES);
    Serial.println(F("First 16 bytes of pkHex:"));
    for (int i = 0; i < 32; i++)
        Serial.print(pkHex[i]);
    Serial.println();

    Serial.print(F("m‑bytes: "));
    Serial.write((uint8_t*)message, msgLen);
    Serial.println();

    delay(500);

    unsigned long t0 = millis();
    int ret = PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(sig, strlen(signatureHex) / 2,
        reinterpret_cast<const uint8_t*>(message), strlen(message), pk);
    unsigned long dt = millis() - t0;

    Serial.printf("verify took %lums\n", dt);
    free(sig);
    free(pk);
    if (ret == SIG_VALID) {
        return true;
    } else {
        return false;
    }
}

#endif // AUTH

/**
 * @brief Read response from server with 5s timeout.
 * @param buffer      Destination buffer
 * @param bufferSize  Maximum size including null terminator
 */
void processResponse(char* buffer, size_t bufferSize)
{
    memset(buffer, 0, bufferSize);
    size_t index = 0;
    unsigned long start = millis();

    // Read data from the server with a 5-second timeout.
    while ((millis() - start) < 5000) {
        while (client.available()) {
            char c = client.read();
            // Serial.print(c); // Optional: echo data
            if (index < (bufferSize - 1)) {
                buffer[index++] = c;
            }
            start = millis(); // Reset timeout
            yield();
        }
        yield();
    }
    Serial.println();
    buffer[index] = '\0'; // Null-terminate the received response
}

/**
 * @brief Check that response length meets expectation.
 * @param response       Null‑terminated response
 * @param expectedLength Minimum expected length
 * @return true if length >= expectedLength
 */
bool checkResponseLength(char* response, size_t expectedLength)
{
    if (strlen(response) >= expectedLength) {
        Serial.println(F("Response OK."));
        return true;
    } else {
        Serial.println(F("Response too short."));
        return false;
    }
}