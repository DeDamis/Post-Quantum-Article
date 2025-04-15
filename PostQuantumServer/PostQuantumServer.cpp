#include "PostQuantumServer.h"

// WinSock headers
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")

#include <string>
#include <sstream>
#include <iostream>
#include <cstring>
#include <ctime>   // for time() to obtain a UNIX timestamp

using namespace std;

int main()
{
    // 1. WinSock initialization
    WSADATA wsaData;
    int wsaResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (wsaResult != 0) {
        cerr << "Error: Unable to initialize WinSock, code: " << wsaResult << endl;
        return 1;
    }

    // 2. Create the listening socket
    SOCKET serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == INVALID_SOCKET) {
        cerr << "Error: Failed to create socket. Code: "
            << WSAGetLastError() << endl;
        WSACleanup();
        return 1;
    }

    // 3. Bind to a specific IP and port
    sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(8080);

    if (bind(serverSocket, reinterpret_cast<sockaddr*>(&serverAddr), sizeof(serverAddr)) == SOCKET_ERROR) {
        cerr << "Error: Failed to bind. Code: "
            << WSAGetLastError() << endl;
        closesocket(serverSocket);
        WSACleanup();
        return 1;
    }

    // 4. Switch to passive mode (listen for incoming connections)
    if (listen(serverSocket, SOMAXCONN) == SOCKET_ERROR) {
        cerr << "Error: Failed to listen. Code: "
            << WSAGetLastError() << endl;
        closesocket(serverSocket);
        WSACleanup();
        return 1;
    }

    cout << "Server is listening on port 8080..." << endl;

    // 5. Main loop to accept connections and then handle communication
    while (true)
    {
        // Accept an incoming connection
        sockaddr_in clientAddr;
        int clientLen = sizeof(clientAddr);
        SOCKET clientSocket = accept(serverSocket, reinterpret_cast<sockaddr*>(&clientAddr), &clientLen);
        if (clientSocket == INVALID_SOCKET) {
            cerr << "Error: Could not accept connection. Code: "
                << WSAGetLastError() << endl;
            // Continue accepting connections despite the failed accept
            continue;
        }

        cout << "A client has connected!" << endl;

        // 6. Communicate with the client as long as they send data or remain connected
        while (true)
        {
            char buffer[1024];
            memset(buffer, 0, sizeof(buffer));

            int bytesRead = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
            if (bytesRead == SOCKET_ERROR) {
                cerr << "Error: Failed to read data from client. Code: "
                    << WSAGetLastError() << endl;
                // End communication with this client
                break;
            }
            else if (bytesRead == 0) {
                // The client closed the connection
                cout << "Client has disconnected." << endl;
                break;
            }

            // Null-terminate the received data to make a string
            buffer[bytesRead] = '\0';

            cout << "Message from client: " << buffer << endl;

            // 7. Process the received message
            // If "AuthRequest" is received, respond with "AuthReply:[timestamp]"
            if (strcmp(buffer, "AuthRequest") == 0) {
                // Get the current UNIX timestamp
                time_t now = time(nullptr);
                string reply = "AuthReply:" + to_string(now);

                // Send the response back to the client
                int sendResult = send(clientSocket, reply.c_str(), static_cast<int>(reply.size()), 0);
                if (sendResult == SOCKET_ERROR) {
                    cerr << "Error: Failed to send AuthReply. Code: "
                        << WSAGetLastError() << endl;
                    break; // End communication with this client
                }
            }
            else {
                // If it's not "AuthRequest," just display the message in the console
                cout << "Message from client: " << buffer << endl;
            }
            // After processing, go back to the beginning of the while loop to read the next message
        }

        // Close the socket for the current client, then go back to waiting for accept() again
        closesocket(clientSocket);
        cout << "Connection with client ended." << endl;
    }

    // If accepting new connections somehow ends (e.g., a signal), we arrive here:
    closesocket(serverSocket);
    WSACleanup();
    return 0;
}
