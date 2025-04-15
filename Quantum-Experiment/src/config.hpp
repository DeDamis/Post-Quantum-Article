#pragma once
#include <Arduino.h>
#include <ESP8266WiFi.h>

#ifdef __cplusplus
extern "C" {
#endif
#include "api.h"  // PQCLEAN_MLDSA65_CLEAN_* function declarations
#ifdef __cplusplus
}
#endif

// Create a global WiFiClient object to manage the TCP connection
WiFiClient client;

bool wifiConnection = false;

uint32_t report_delay = 500;
uint32_t tcp_delay = 5000;
uint32_t WiFi_retry_delay = 10000;

// Attempts to connect to the TCP server
bool connectToServer();
