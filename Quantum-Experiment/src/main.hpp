#pragma once
#include <Arduino.h>
#include <ESP8266WiFi.h>

extern "C" {
#include "aes.h"
#include "crypto_kem/ml-kem-512/clean/api.h" // PQCLEAN_MLDSA44_CLEAN_* function declarations
#include "crypto_sign/ml-dsa-44/clean/api.h" // PQCLEAN_MLDSA44_CLEAN_* function declarations
}

// Global variable for the kem shared secret, that is used as secret key for AES encryption
#ifdef KEM
static uint8_t kem_shared_secret[PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES];
#endif

// Create a global WiFiClient object to manage the TCP connection
WiFiClient client;

size_t bufferSize = 5000; // Buffer size for the tcp message readout

bool wifiConnection = false;

static const int SIG_VALID = 0;
static const int SIG_INVALID = -1;

// Attempts to connect to the TCP server
bool connectToServer();

void processResponse(char* buffer, size_t bufferSize);

bool processKem(char* message, size_t bufferSize);

bool checkResponseLength(char* response, size_t expectedLength);

bool processAuthReply(char* reply);

bool verifyAuthReply(const char* message, const char* signatureHex, const char* pkHex);