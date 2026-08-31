#include "net_utils.h"

uint16_t checksum16(const void *data, size_t len) {
    /* RFC 1071 16 bit checksum */
    const uint16_t *data_int16 = (const uint16_t *)data;
    uint32_t sum = 0;
    for (int i = 0; i < len / 2; i++) {
        sum += data_int16[i];
    }

    if (len % 2 != 0) {
        uint8_t last_byte = ((const uint8_t *)data)[len - 1];
        uint16_t odd_word = 0;
        *(uint8_t *)&odd_word = last_byte;
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