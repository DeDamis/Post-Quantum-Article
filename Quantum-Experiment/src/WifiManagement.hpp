#pragma once
#include <ESP8266WiFi.h>

// Attempts to connect to Wi-Fi
bool establishWifiConnection();

// Prints Wi-Fi info to serial
void getWifiInfo();

void listAvailableNetworks();
