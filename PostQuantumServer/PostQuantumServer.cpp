#include "PostQuantumServer.h"

// Hlavičky WinSock
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")

#include <string>
#include <sstream>
#include <iostream>
#include <cstring>
#include <ctime>   // kvůli time() pro Unix timestamp

using namespace std;

int main()
{
    // 1. Inicializace knihovny WinSock
    WSADATA wsaData;
    int wsaResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (wsaResult != 0) {
        std::cerr << "Chyba: Nelze inicializovat WinSock, kód: " << wsaResult << std::endl;
        return 1;
    }

    // 2. Vytvoření poslouchacího socketu
    SOCKET serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == INVALID_SOCKET) {
        std::cerr << "Chyba: Nepodařilo se vytvořit socket. Kód: "
            << WSAGetLastError() << std::endl;
        WSACleanup();
        return 1;
    }

    // 3. Bind na konkrétní IP a port
    sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(8080);

    if (bind(serverSocket, reinterpret_cast<sockaddr*>(&serverAddr), sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "Chyba: Nepodařilo se provést bind. Kód: "
            << WSAGetLastError() << std::endl;
        closesocket(serverSocket);
        WSACleanup();
        return 1;
    }

    // 4. Nastavit do pasivního režimu
    if (listen(serverSocket, SOMAXCONN) == SOCKET_ERROR) {
        std::cerr << "Chyba: Nepodařilo se naslouchat (listen). Kód: "
            << WSAGetLastError() << std::endl;
        closesocket(serverSocket);
        WSACleanup();
        return 1;
    }

    std::cout << "Server naslouchá na portu 8080..." << std::endl;

    // 5. Hlavní smyčka pro přijímání spojení a následnou komunikaci
    while (true)
    {
        // Přijetí příchozího spojení
        sockaddr_in clientAddr;
        int clientLen = sizeof(clientAddr);
        SOCKET clientSocket = accept(serverSocket, reinterpret_cast<sockaddr*>(&clientAddr), &clientLen);
        if (clientSocket == INVALID_SOCKET) {
            std::cerr << "Chyba: Nepodařilo se přijmout spojení. Kód: "
                << WSAGetLastError() << std::endl;
            // Pokračujeme dál, aby server běžel i po neúspěšném acceptu
            continue;
        }

        std::cout << "Připojil se klient!" << std::endl;

        // 6. Komunikace s klientem – v smyčce dokud klient neposílá data, nebo neodpojí
        while (true)
        {
            char buffer[1024];
            memset(buffer, 0, sizeof(buffer));

            int bytesRead = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
            if (bytesRead == SOCKET_ERROR) {
                std::cerr << "Chyba: Nepodařilo se přečíst data od klienta. Kód: "
                    << WSAGetLastError() << std::endl;
                // Ukončíme komunikaci s tímto klientem
                break;
            }
            else if (bytesRead == 0) {
                // Klient zavřel spojení
                std::cout << "Klient ukončil spojení." << std::endl;
                break;
            }

            // Přijmutá data ukončíme nulou, abychom měli řetězec
            buffer[bytesRead] = '\0';

            std::cout << "Zpráva od klienta: " << buffer << std::endl;

            // 7. Zpracování přijaté zprávy
            // Když přijde "AuthRequest", odpovíme "AuthReply:[timestamp]"
            if (strcmp(buffer, "AuthRequest") == 0) {
                // Získáme aktuální UNIX timestamp
                std::time_t now = std::time(nullptr);
                std::string reply = "AuthReply:" + std::to_string(now);

                // Odeslání odpovědi klientovi
                int sendResult = send(clientSocket, reply.c_str(), static_cast<int>(reply.size()), 0);
                if (sendResult == SOCKET_ERROR) {
                    std::cerr << "Chyba: Nepodařilo se odeslat AuthReply. Kód: "
                        << WSAGetLastError() << std::endl;
                    break; // Ukončíme komunikaci s klientem
                }
            }
            else {
                // Pokud nepřišel "AuthRequest", pouze zobrazíme zprávu v konzoli
                std::cout << "Zpráva od klienta: " << buffer << std::endl;
            }
            // Po zpracování se vracíme na začátek while smyčky (čteme další zprávu)
        }

        // Zavřeme socket vůči aktuálnímu klientovi, pak jdeme zase čekat na další accept()
        closesocket(clientSocket);
        std::cout << "Spojení s klientem ukončeno." << std::endl;
    }

    // Pokud by se nějak ukončilo acceptování (např. signál), dojdeme až sem:
    closesocket(serverSocket);
    WSACleanup();
    return 0;
}
