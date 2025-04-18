#include "ML_DSA_PublicKey.hpp"
#include "WifiManagement.hpp"
#include "config.hpp"
#include "helpers.hpp"

// hard-coded server’s IP address and port
const char* serverIP = "192.168.238.1"; // Example IP
const uint16_t serverPort = 8080; // Example port

// Global variable for the kem shared secret, that is used as secret key for AES encryption
static uint8_t kem_shared_secret[PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES];

void setup()
{
    ESP.wdtEnable(10000); // TODO CHECK
    Serial.begin(115200); // Start serial for debug output
    delay(200); // Let the serial line settle
    Serial.println(F("Booting up..."));

    // Try to connect to Wi-Fi
    // wifiConnection = establishWifiConnection();

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
    if (millis() > (tcp_delay + 10000)) {
        if (wifiConnection && !client.connected()) {
            // Proceed with a handshake
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
            // Serial.println(WiFi.status());
        }
    }
}

bool connectToServer()
{
    Serial.print("Free heap: ");
    Serial.println(ESP.getFreeHeap());

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
    delay(500);

    // Receive a message in a format of
    // AuthReply:[UNIX timestamp]|signature:[ML-DSA-Signature]

    // Allocate a response buffer from the heap.
    size_t bufferSize = 7000; // Adjust if necessary
    char* response = (char*)malloc(bufferSize);
    if (!response) {
        Serial.println(F("Failed to allocate memory for response."));
        return false;
    }

    processResponse(response, bufferSize);

    checkResponseLength(response, PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES);

    // We should fix the signing check first
    if (processAuthReply(response)) { // Server signature valid
        Serial.println(F("Sig valid. Continuing.."));
        Serial.print("Free heap: ");
        Serial.println(ESP.getFreeHeap());
        client.println("Ack");
        delay(500);
        // Proceed with KEM Request
        client.println("KemRequest");
        delay(500);
        processResponse(response, bufferSize);
        // processKem(response, bufferSize);
        // client.println(response);
        //    send an AES-encrypted message to server "Post-Quantum Cryptography is Awesome."
    }
    client.abort();
    free(response);
    return true;
}

bool processKem(char* message, size_t bufferSize)
{
    const char* prefix = "KemInit:";
    const size_t prefixLen = strlen(prefix);
    /* --- 1. sanity‑check prefix ------------------------------------ */
    if (strncmp(message, prefix, prefixLen) != 0) {
        Serial.println(F("Wrong control word received. Expected KemInit."));
        return false;
    }
    yield();
    /* --- 2. locate and length‑check pkHEX -------------------------- */
    char* pkHex = message + prefixLen; // pointer to first hex digit
    size_t pkHexLen = strlen(pkHex);
    const size_t pkBytes = PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES;
    if (pkHexLen != pkBytes * 2) { // must be 800 × 2 = 1600 hex
        Serial.println(F("KEM: pk hex length mismatch"));
        return false;
    }
    yield();
    /* --- 3. hex → raw public key ----------------------------------- */
    static uint8_t pk[pkBytes];
    if (!hexToBytes(pkHex, pk, pkBytes)) {
        Serial.println(F("KEM: pk hex decode failed"));
        return false;
    }
    yield();
    /* --- 4. encapsulate  ------------------------------------------- */
    const size_t ctBytes = PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES;
    uint8_t ct[ctBytes];
    system_soft_wdt_stop(); // disable **all** WDTs (hard & soft)
    unsigned long t0 = millis();
    // I have verified that this will cause the wdt reset
    if (PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(ct, kem_shared_secret, pk) != 0) {
        Serial.println(F("KEM: kem_enc failed"));
        return false;
    }
    unsigned long dt = millis() - t0;
    system_soft_wdt_restart(); // re-enable both WDTs

    Serial.printf("encapsulation took %lums\n", dt);
    yield();
    // --- 5. ciphertext → hex ---------------------------------------
    static char ctHex[ctBytes * 2 + 1]; // 1537 bytes
    if (!bytesToHex(ct, ctBytes, ctHex, sizeof(ctHex))) {
        Serial.println(F("KEM: bytesToHex failed"));
        return false;
    }
    yield();
    const char* ctPrefix = "KemCipher:";
    size_t needed = strlen(ctPrefix) + strlen(ctHex) + 1;

    if (needed > bufferSize) { // guard overflow
        Serial.println(F("KEM: buffer too small"));
        return false;
    }
    yield();
    // --- 6. overwrite original buffer ------------------------------
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
        return false;
    }
    *colon1 = '\0';
    char* control = reply; // should be "AuthReply"

    // The rest should contain the timestamp followed by a pipe.
    char* rest = colon1 + 1;
    char* pipePos = strchr(rest, '|');
    if (!pipePos) {
        Serial.println(F("Error: pipe not found."));
        return false;
    }
    *pipePos = '\0';
    char* timestampStr = rest;
    // Expect the "signature:" label after the pipe.
    const char* sigLabel = "signature:";
    char* signatureStart = strstr(pipePos + 1, sigLabel);
    if (!signatureStart) {
        Serial.println(F("Error: signature label not found."));
        return false;
    }
    signatureStart += strlen(sigLabel); // Move pointer to start of hex signature

    // Debug print parsed values.
    /*
    Serial.println(F("Parsed Values:"));
    Serial.println(F("Control word: "));
    Serial.println(control);
    Serial.println(F("Timestamp: "));
    Serial.println(timestampStr);
    Serial.println(F("Signature: "));
    Serial.println(signatureStart);
    */

    // Construct the original message that was signed:
    // "AuthReply:<timestamp>"
    static char message[100]; // Should be plenty; adjust if needed.
    snprintf(message, sizeof(message), "%s:%s", control, timestampStr);
    // Serial.print(F("Message for verification: "));
    // Serial.println(message);
    //  Get the public key from PROGMEM (assumed to be defined in dilithiumPublicKey)
    char* pkHex = (char*)malloc(((PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES * 2) + 1) * sizeof(char));
    if (!pkHex) {
        Serial.println(F("Failed to allocate memory for pkHex."));
        return false;
    }
    strcpy_P(pkHex, dilithiumPublicKey);

    // Verify the signature.
    bool valid = verifyAuthReply(message, signatureStart, pkHex);
    free(pkHex);
    if (valid) {
        Serial.println(F("Signature is VALID."));
        return true;
    } else {
        Serial.println(F("Signature is INVALID."));
        return false;
    }
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
        return false;
    }

    if (!hexToBytes(pkHex, pk, PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES)) {
        Serial.println(F("Public key hex decode failed."));
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

    delay(1000);
    // ** Disable ALL WDTs **
    ESP.wdtDisable(); // TODO CHECK

    // ** Stop both soft & hard WDTs **
    system_soft_wdt_stop(); // TODO CHECK

    unsigned long t0 = millis();
    int ret = PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(sig, strlen(signatureHex) / 2,
        reinterpret_cast<const uint8_t*>(message), strlen(message), pk);
    unsigned long dt = millis() - t0;

    // ** Restart the hardware watchdog **
    system_soft_wdt_restart(); // TODO CHECK

    // ** Re‑enable hardware & software WDT, give it a 5 s window **
    ESP.wdtEnable(5000); // TODO CHECK

    Serial.printf("verify took %lums\n", dt);
    free(sig);
    free(pk);
    if (ret == SIG_VALID) {
        return true;
    } else {
        return false;
    }
}

void processResponse(char* buffer, size_t bufferSize)
{
    for (size_t i = 0; i < bufferSize; i++) {
        buffer[i] = '\0';
    }

    size_t index = 0;
    unsigned long start = millis();

    // Read data from the server with a 5-second timeout.
    while ((millis() - start) < 5000) {
        while (client.available()) {
            char c = client.read();
            Serial.print(c); // Optional: echo data
            if (index < (bufferSize - 1)) { // leave room for null terminator
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

bool checkResponseLength(char* response, size_t expectedLength)
{
    if (strlen(response) >= expectedLength) {
        Serial.println(F("Response OK."));
        return true;
    } else {
        Serial.println(F("Response error. Response is shorter than expected"));
        return false;
    }
}