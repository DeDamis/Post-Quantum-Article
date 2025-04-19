# Post‑Quantum Cryptography Playground

A two‑part research playground for experimenting with NIST‑candidate post‑quantum cryptography (PQC) algorithms on both server‑class machines and resource‑constrained microcontrollers.

## Project Highlights

- ⚡ **High‑performance C++ server** that exposes KEM (key encapsulation) and digital signature endpoints built with the PQClean implementations.  
- 🔬 **Embedded “Quantum‑Experiment”** built with PlatformIO targeting ESP32/ESP8266 to evaluate memory footprint of the same PQC primitives.  
- 🔄 **Interoperability**: identical C reference implementations shared between targets to ensure apples‑to‑apples benchmarking.  
- 📝 **Self‑contained**: PQClean is vendored; no external submodules or system‑wide installs required.  

## Directory Layout

```text
.
├── LICENSE                   # MIT licence for original code
├── PostQuantumServer/        # C++17 server application
│   ├── PostQuantumServer.cpp
│   ├── Helpers.*
│   └── PQClean-master/       # Vendored cryptographic primitives
└── Quantum-Experiment/       # PlatformIO project for MCU boards
    ├── src/
    ├── include/
    └── lib/
```

## Quick Start

### 1. Build & Run the Server

**Requirements**

- C++17 compiler (g++ ≥ 10 / clang ≥ 11 / MSVC ≥ 19.28)
- CMake ≥ 3.15

### 2. Flash the Microcontroller Demo

**Requirements**

- [PlatformIO CLI](https://docs.platformio.org/) ≥ 6.1
- Espressif ESP8266 based board

Edit the `user-config.hpp`, build and flash the project to the board.

## Security Notice

This is **research code**. Do **not** deploy it in production systems.

## License

The original code in this repository is released under the MIT License  
(see `LICENSE`). Vendored code under `PQClean-master` retains its  
upstream licensing (mainly CC‑0 and MIT). See individual files.

## Acknowledgements

- [PQClean](https://github.com/PQClean/PQClean) for clean, portable implementations of PQC schemes.  
- The authors of Kyber and Dilithium
