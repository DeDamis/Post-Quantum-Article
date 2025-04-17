#include "PostQuantumServer.h"

// WinSock headers
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")

#include <string>
#include <sstream>
#include <iostream>
#include <cstring>
#include <vector>
#include <ctime>    // for time() to obtain a UNIX timestamp

#ifdef __cplusplus
	extern "C" {
#endif
	#include "PQClean-master/crypto_sign/ml-dsa-44/clean/api.h"  // PQCLEAN_MLDSA44_CLEAN_* function declarations
	#include "PQClean-master/crypto_kem/ml-kem-512/clean/api.h"  // PQCLEAN_MLKEM512_CLEAN_* function declarations
	#include "aes.h"
#ifdef __cplusplus
	}
#endif

#include "Helpers.hpp"  // Our custom helper functions (bytesToHex, etc.)

using namespace std;

static uint8_t kem_shared_secret[PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES];

int main()
{
	// Prepare buffers for keys
	uint8_t pk[PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES];
	uint8_t sk[PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES];
	// KEM keys
	uint8_t kem_pk[PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES];
	uint8_t kem_sk[PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES];

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

				if (strcmp(buffer, "KemRequest") == 0) {
					// 1) Vygeneruj KEM klíče
					if (PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(kem_pk, kem_sk) != 0) {
						cerr << "Error: KEM keypair generation failed" << endl;
						break;
					}

					// 2) Převod veřejného klíče na hex
					string pkHex = bytesToHex(kem_pk, sizeof(kem_pk));

					// 3) Sestav odpověď a pošli
					string kemReply = "KemInit:" + pkHex;
					if (send(clientSocket,
						kemReply.c_str(),
						static_cast<int>(kemReply.size()),
						0) == SOCKET_ERROR) {
						cerr << "Error: Failed to send KemInit. Code: "
							<< WSAGetLastError() << endl;
						break;
					}
				}
				else if (strncmp(buffer, "KemCipher:", 10) == 0) {
					// 1) Extrahuj hex‑část za "KemCipher:"
					std::string hexCt(buffer + 10);

					// 2) Převeď hex na binární ciphertext
					std::vector<uint8_t> ciphertext(PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES);
					if (!hexToBytes(hexCt, ciphertext.data(), ciphertext.size())) {
						cerr << "Error: Invalid ciphertext format" << endl;
						break;
					}

					// 3) Dekapsulace 
					int decRet = PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(
						kem_shared_secret,            // výstup: shared secret
						ciphertext.data(),            // vstup: ciphertext
						kem_sk                        // secret key pro KEM
					);
					if (decRet != 0) {
						cerr << "Error: KEM decapsulation failed" << endl;
						break;
					}
					string reply = "LineReady";
					if (send(clientSocket, reply.c_str(), static_cast<int>(reply.size()), 0) == SOCKET_ERROR) {
						cerr << "Error: Failed to send LineReady. Code: "
							<< WSAGetLastError() << endl;
						break;
					}
					cout << "Shared secret decapsulated and stored." << endl;
				}
				else if (strncmp(buffer, "ConfidentialData:", 17) == 0) {
					// 1) Extract the hex payload after "ConfidentialData:"
					std::string hexData(buffer + 17);

					// 2) Decode hex into bytes
					size_t dataLen = hexData.size() / 2;
					std::vector<uint8_t> encData(dataLen);
					if (!hexToBytes(hexData, encData.data(), dataLen)) {
						std::cerr << "Error: Invalid ConfidentialData format" << std::endl;
						break;
					}

					// 3) Split nonce (first AESCTR_NONCEBYTES) and ciphertext
					const size_t nonceLen = AESCTR_NONCEBYTES;
					if (dataLen < nonceLen) {
						std::cerr << "Error: Encrypted data too short for nonce" << std::endl;
						break;
					}
					const uint8_t* iv = encData.data();
					size_t ctLen = dataLen - nonceLen;
					const uint8_t* ciphertext = encData.data() + nonceLen;

					// 4) AES‑256‑CTR key schedule using the shared secret
					aes256ctx aesCtx;
					aes256_ctr_keyexp(&aesCtx, kem_shared_secret);

					// 5) Decrypt ciphertext
					std::vector<uint8_t> plaintext(ctLen);
					aes256_ctr(plaintext.data(), ctLen, iv, &aesCtx);

					// 6) Clean up AES context
					aes256_ctx_release(&aesCtx);

					// 7) Convert plaintext bytes to string and print
					std::string message(reinterpret_cast<char*>(plaintext.data()), plaintext.size());
					std::cout << "Decrypted ConfidentialData: " << message << std::endl;
				}
				// 7. Process the received message
				else if (strcmp(buffer, "AuthRequest") == 0) {
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

					int ret = PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(signature, sigLen, reinterpret_cast<const uint8_t*>(replyPlain.data()), replyPlain.size(), pk);

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
