#include <user_interface.h>

extern "C" int randombytes(uint8_t *output, size_t n) {
    // Fill 'output' with 'n' random bytes
    // os_get_random() returns up to 256 bytes at once, so break into chunks if needed.
    size_t offset = 0;
    while (offset < n) {
        size_t chunk = (n - offset) > 256 ? 256 : (n - offset);
        os_get_random(output + offset, chunk);
        offset += chunk;
    }
    return 0;
}

// The library apparently calls this name, so forward to ours
extern "C" int PQCLEAN_randombytes(uint8_t *output, size_t n) {
    return randombytes(output, n);
}