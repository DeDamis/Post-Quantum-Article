#pragma once
#include <Arduino.h>
#include <ESP8266WiFi.h>

extern "C" {
#include "aes.h" // AES‑256‑CTR
#include "crypto_kem/ml-kem-512/clean/api.h" // ML-KEM key encapsulation
#include "crypto_sign/ml-dsa-44/clean/api.h" // ML-DSA signatures
}

WiFiClient client;
size_t bufferSize = 5000; // Buffer size for the tcp message readout
bool wifiConnection = false;

size_t WiFi_retry = 0;
size_t report_stamp = 0;
size_t tcp_stamp = 0;

static const int SIG_VALID = 0;
static const int SIG_INVALID = -1;

// TCP connection and protocol handlers
bool connectToServer();
void processResponse(char* buffer, size_t bufferSize);
bool checkResponseLength(char* response, size_t expectedLength);

bool processKem(char* message, size_t bufferSize);

bool processAuthReply(char* reply);
bool verifyAuthReply(const char* message, const char* signatureHex, const char* pkHex);