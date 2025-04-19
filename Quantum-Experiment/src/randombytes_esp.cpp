#include <user_interface.h>

/**
 * Fills `output` with `n` random bytes using ESP8266’s os_get_random().
 */
extern "C" int randombytes(uint8_t* output, size_t n)
{
    size_t offset = 0;
    while (offset < n) {
        size_t chunk = (n - offset) > 256 ? 256 : (n - offset);
        os_get_random(output + offset, chunk);
        offset += chunk;
    }
    return 0;
}

/** Alias for PQClean compatibility. */
extern "C" int PQCLEAN_randombytes(uint8_t* output, size_t n)
{
    return randombytes(output, n);
}