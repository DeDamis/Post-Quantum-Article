#include "PostQuantumServer.h"

// WinSock headers
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")

#include <string>
#include <sstream>
#include <iostream>
#include <cstring>
#include <ctime>    // for time() to obtain a UNIX timestamp

#ifdef __cplusplus
extern "C" {
#endif
#include "api.h"  // PQCLEAN_MLDSA44_CLEAN_* function declarations
#ifdef __cplusplus
}
#endif

#include "Helpers.hpp"  // Our custom helper functions (bytesToHex, etc.)

using namespace std;

int main()
{
	// Prepare buffers for keys
	uint8_t pk[PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES];
	uint8_t sk[PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES];

	// Attempt to load existing keys from files
	bool pkLoaded = loadKeyFromFile("PublicKeyDilithium.txt", pk, sizeof(pk));
	bool skLoaded = loadKeyFromFile("SecretKeyDilithium.txt", sk, sizeof(sk));

	if (pkLoaded && skLoaded) {
		cout << "Existing keys loaded from files." << endl;
	}
	else {
		// If files do not exist or fail to load, generate a new keypair
		cout << "No existing keys found. Generating new keys..." << endl;
		if (PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(pk, sk) == 0) {
			// Save them
			if (!saveKeyToFile("PublicKeyDilithium.txt", pk, sizeof(pk)) ||
				!saveKeyToFile("SecretKeyDilithium.txt", sk, sizeof(sk))) {
				cerr << "Error: Could not save generated keys to files." << endl;
			}
			else {
				cout << "Keys generated and saved to PublicKeyDilithium.txt/SecretKeyDilithium.txt" << endl;
			}
		}
		else {
			cerr << "Key generation failed!" << endl;
			return 1;
		}
	}

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
	while (true) {
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
		while (true) {
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

			if (bytesRead > 2) {
				cout << "Message from client: " << buffer << endl;

				// 7. Process the received message
				if (strcmp(buffer, "AuthRequest") == 0) {
					// Build the message we want to sign
					time_t now = time(nullptr);
					string replyPlain = "AuthReply:" + to_string(now);

					// Sign the reply with the secret key
					// We store the result in signature[] with length sigLen
					uint8_t signature[PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES];
					size_t sigLen = 0;

					int signResult = PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(
						signature,          // output buffer for the signature
						&sigLen,            // (out) the signature length
						reinterpret_cast<const uint8_t*>(replyPlain.data()),
						replyPlain.size(),  // message size
						sk                  // secret key
					);

					if (signResult != 0) {
						cerr << "Error: Could not sign the message with ML-DSA." << endl;
						break;
					}

					// Convert signature to hex to send easily
					string signatureHex = bytesToHex(signature, sigLen);

					// Combine the original reply and the signature in one message
					// You could do something like "AuthReply:<timestamp>||sig:<signatureHex>"
					// or use JSON, or separate them in any protocol format you want.
					// For example:
					string combinedMessage = replyPlain + "|signature:" + signatureHex;

					// Send the combined reply+signature to the client
					int sendResult = send(clientSocket,
						combinedMessage.c_str(),
						static_cast<int>(combinedMessage.size()),
						0);
					if (sendResult == SOCKET_ERROR) {
						cerr << "Error: Failed to send signed AuthReply. Code: "
							<< WSAGetLastError() << endl;
						break; // End communication with this client
					}
				}
				else if (strcmp(buffer, "Ack") == 0) { 1; }
				else {
					// If it's not "AuthRequest," just display the message in the console
					cout << "Message from client: " << buffer << endl;
				}
			}
			// After processing, go back to read the next message
		}

		// Close the socket for the current client, then loop back for a new accept()
		closesocket(clientSocket);
		cout << "Connection with client ended." << endl;
	}

	// If accepting new connections somehow ends, we arrive here:
	closesocket(serverSocket);
	WSACleanup();
	return 0;
}
