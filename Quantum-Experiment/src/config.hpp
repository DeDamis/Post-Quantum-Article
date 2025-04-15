#pragma once
#include <Arduino.h>
#include <ESP8266WiFi.h>

bool wifiConnection = false;

uint32_t report_delay = 500;
uint32_t tcp_delay = 5000;
uint32_t WiFi_retry_delay = 10000;

// Attempts to connect to Wi-Fi
bool establishWifiConnection();

// Prints Wi-Fi info to serial
void getWifiInfo();

// Attempts to connect to the TCP server
bool connectToServer();

void listAvailableNetworks();