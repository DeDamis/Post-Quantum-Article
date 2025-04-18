// PostQuantumServer.cpp
/**
 * @file PostQuantumServer.cpp
 * @brief Entry point for a WinSock‑based post‑quantum cryptography server.
 */

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
#include <ctime>      ///< for time()
#include "Helpers.hpp"

extern "C" {
#include "PQClean-master/crypto_sign/ml-dsa-44/clean/api.h"   ///< ML-DSA signatures
#include "PQClean-master/crypto_kem/ml-kem-512/clean/api.h"   ///< ML-KEM key encapsulation
#include "aes.h"                                             ///< AES‑256‑CTR
}

using namespace std;

static uint8_t kem_shared_secret[PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES];
const int MAX_MSG = 2048;

/**
 * @brief Entry point: initialize keys, start server, and process clients.
 * @return 0 on clean exit; nonzero on error.
 */
int main() {
    // Prepare Dilithium signature key buffers
    uint8_t pk[PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES];
    // Prepare KEM key buffers
    uint8_t kem_pk[PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t kem_sk[PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES];

    // Attempt to load existing keys
    bool pkLoaded = loadKeyFromFile("PublicKeyDilithium.txt", pk, sizeof(pk));
    bool skLoaded = loadKeyFromFile("SecretKeyDilithium.txt", sk, sizeof(sk));
    if (pkLoaded && skLoaded) {
        cout << "Existing keys loaded from files." << endl;
    }
    else {
        cout << "No existing keys found. Generating new keys..." << endl;
        if (PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(pk, sk) == 0) {
            if (!saveKeyToFile("PublicKeyDilithium.txt", pk, sizeof(pk)) ||
                !saveKeyToFile("SecretKeyDilithium.txt", sk, sizeof(sk))) {
                cerr << "Error: Could not save generated keys." << endl;
            }
            else {
                cout << "Keys generated and saved to files." << endl;
            }
        }
        else {
            cerr << "Error: Key generation failed!" << endl;
            return 1;
        }
    }

    // Step 1: Initialize WinSock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        cerr << "Error: WinSock initialization failed." << endl;
        return 1;
    }

    // Step 2: Create listening socket
    SOCKET serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == INVALID_SOCKET) {
        cerr << "Error: Socket creation failed. Code: " << WSAGetLastError() << endl;
        WSACleanup();
        return 1;
    }

    // Step 3: Bind to port 8080 on any interface
    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(8080);
    if (bind(serverSocket, reinterpret_cast<sockaddr*>(&serverAddr), sizeof(serverAddr)) == SOCKET_ERROR) {
        cerr << "Error: Bind failed. Code: " << WSAGetLastError() << endl;
        closesocket(serverSocket);
        WSACleanup();
        return 1;
    }

    // Step 4: Listen for incoming connections
    if (listen(serverSocket, SOMAXCONN) == SOCKET_ERROR) {
        cerr << "Error: Listen failed. Code: " << WSAGetLastError() << endl;
        closesocket(serverSocket);
        WSACleanup();
        return 1;
    }
    cout << "Server listening on port 8080..." << endl;

    // Step 5: Accept and handle client connections
    while (true) {
        sockaddr_in clientAddr;
        int clientLen = sizeof(clientAddr);
        SOCKET clientSocket = accept(serverSocket, reinterpret_cast<sockaddr*>(&clientAddr), &clientLen);
        if (clientSocket == INVALID_SOCKET) {
            cerr << "Error: Accept failed. Code: " << WSAGetLastError() << endl;
            continue;
        }
        cout << "Client connected." << endl;

        // Communicate until client disconnects or error
        while (true) {
            char buffer[MAX_MSG]{};
            int bytesRead = recv(clientSocket, buffer, MAX_MSG - 1, 0);
            if (bytesRead == SOCKET_ERROR) {
                cerr << "Error: recv() failed. Code: " << WSAGetLastError() << endl;
                break;
            }
            if (bytesRead == 0) {
                cout << "Client disconnected." << endl;
                break;
            }
            buffer[bytesRead] = '\0';

            // Handle messages longer than 2 bytes
            if (bytesRead > 2) {
                if (strcmp(buffer, "KemRequest") == 0) {
                    // Step 1: Generate KEM key pair
                    if (PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(kem_pk, kem_sk) != 0) {
                        cerr << "Error: KEM key generation failed." << endl;
                        break;
                    }
                    // Step 2: Hex‑encode public key
                    string pkHex = bytesToHex(kem_pk, sizeof(kem_pk));
                    // Step 3: Send “KemInit:<hex>”
                    string reply = "KemInit:" + pkHex;
                    if (send(clientSocket, reply.c_str(), static_cast<int>(reply.size()), 0) == SOCKET_ERROR) {
                        cerr << "Error: send(KemInit) failed." << endl;
                        break;
                    }
                }
                else if (strncmp(buffer, "KemCipher:", 10) == 0) {
                    // Step 1: Extract hex payload
                    string hexCt(buffer + 10);
                    // Step 2: Decode hex to ciphertext
                    vector<uint8_t> ciphertext(PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES);
                    if (!hexToBytes(hexCt, ciphertext.data(), ciphertext.size())) {
                        cerr << "Error: Invalid ciphertext format." << endl;
                        break;
                    }
                    // Step 3: Decapsulate to shared secret
                    if (PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(kem_shared_secret,
                        ciphertext.data(),
                        kem_sk) != 0) {
                        cerr << "Error: KEM decapsulation failed." << endl;
                        break;
                    }
                    // Step 4: Notify client
                    if (send(clientSocket, "LineReady", 9, 0) == SOCKET_ERROR) {
                        cerr << "Error: send(LineReady) failed." << endl;
                        break;
                    }
                    cout << "Shared secret established." << endl;
                }
                else if (strncmp(buffer, "ConfidentialData:", 17) == 0) {
                    // Step 1: Extract hex‑encoded payload
                    string hexData(buffer + 17);
                    size_t totalLen = hexData.size() / 2;
                    vector<uint8_t> encData(totalLen);
                    if (!hexToBytes(hexData, encData.data(), totalLen)) {
                        cerr << "Error: Invalid encrypted data." << endl;
                        break;
                    }
                    // Step 2: Separate nonce and ciphertext
                    constexpr size_t nonceLen = AESCTR_NONCEBYTES;
                    if (totalLen < nonceLen) {
                        cerr << "Error: Data too short for nonce." << endl;
                        break;
                    }
                    const uint8_t* iv = encData.data();
                    size_t ctLen = totalLen - nonceLen;
                    const uint8_t* ct = encData.data() + nonceLen;
                    // Step 3: Decrypt with AES‑256‑CTR
                    aes256ctx aesCtx;
                    aes256_ctr_keyexp(&aesCtx, kem_shared_secret);
                    vector<uint8_t> plain(ctLen);
                    aes256_ctr(plain.data(), ctLen, iv, &aesCtx);
                    aes256_ctx_release(&aesCtx);
                    // Step 4: Print decrypted message
                    cout << "Decrypted data: "
                        << string(reinterpret_cast<char*>(plain.data()), plain.size())
                        << endl;
                }
                else if (strcmp(buffer, "AuthRequest") == 0) {
                    // Step 1: Prepare timestamped reply
                    time_t now = time(nullptr);
                    string plain = "AuthReply:" + to_string(now);
                    // Step 2: Sign reply with Dilithium
                    uint8_t signature[PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES];
                    size_t sigLen = 0;
                    if (PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(signature, &sigLen,
                        reinterpret_cast<const uint8_t*>(plain.data()),
                        plain.size(), sk) != 0) {
                        cerr << "Error: Signature failed." << endl;
                        break;
                    }
                    // Step 3: Verify and send combined message
                    string sigHex = bytesToHex(signature, sigLen);
                    string combined = plain + "|signature:" + sigHex;
                    if (send(clientSocket, combined.c_str(), static_cast<int>(combined.size()), 0) == SOCKET_ERROR) {
                        cerr << "Error: send(AuthReply) failed." << endl;
                        break;
                    }
                }
                else {
                    // Unrecognized message: just echo to console
                    cout << "Client: " << buffer << endl;
                }
            }
        }

        // Clean up connection
        closesocket(clientSocket);
        cout << "Connection closed." << endl;
    }

    // Shutdown server
    closesocket(serverSocket);
    WSACleanup();
    return 0;
}
