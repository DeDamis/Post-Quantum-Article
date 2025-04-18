#pragma once
#include <Arduino.h>
#include <ESP8266WiFi.h>

#ifdef __cplusplus
extern "C" {
#endif
#include "aes.h"
#include "crypto_kem/ml-kem-512/clean/api.h" // PQCLEAN_MLDSA44_CLEAN_* function declarations
#include "crypto_sign/ml-dsa-44/clean/api.h" // PQCLEAN_MLDSA44_CLEAN_* function declarations
#ifdef __cplusplus
}
#endif

// Create a global WiFiClient object to manage the TCP connection
WiFiClient client;

bool wifiConnection = false;

uint32_t report_delay = 500;
uint32_t tcp_delay = 5000;
uint32_t WiFi_retry_delay = 10000;

static const int SIG_VALID = 0;
static const int SIG_INVALID = -1;

// Attempts to connect to the TCP server
bool connectToServer();

void processResponse(char* buffer, size_t bufferSize);

bool processKem(char* message, size_t bufferSize);

bool checkResponseLength(char* response, size_t expectedLength);

bool processAuthReply(char* reply);

bool verifyAuthReply(const char* message, const char* signatureHex, const char* pkHex);