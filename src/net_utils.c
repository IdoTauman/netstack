#include <linux/string.h>
#include "net_utils.h"

uint16_t checksum16(const void *data, size_t len) {
    /* RFC 1071 16-bit checksum.
     *
     * Read via memcpy into a local, correctly-aligned uint16_t rather than
     * casting `data` to `const uint16_t *` and dereferencing directly:
     * network buffers are not guaranteed to be 2-byte aligned, and an
     * unaligned load through a typed pointer is undefined behavior /
     * a fault on strict-alignment architectures. Compilers turn the
     * memcpy into a plain load wherever unaligned access is cheap, so
     * this costs nothing on x86. */
    const uint8_t *p = (const uint8_t *)data;
    uint32_t sum = 0;
    size_t i;

    for (i = 0; i + 1 < len; i += 2) {
        uint16_t word;
        memcpy(&word, p + i, sizeof(word));
        sum += word;
    }

    if (len & 1) {
        uint16_t odd_word = 0;
        ((uint8_t *)&odd_word)[0] = p[len - 1];
        sum += odd_word;
    }

    return checksum_fold(sum);
}

uint16_t checksum_fold(uint32_t sum) {
    /* Folds 32-bit carries back into the lower 16 bits */
    while (sum > 0xFFFF) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (uint16_t)(~sum);
}