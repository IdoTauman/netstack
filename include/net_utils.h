#ifndef NET_UTILS_H
#define NET_UTILS_H

#include <linux/types.h>
#include <stddef.h>

/* 16-bit One's Complement Checksum (RFC 1071) */
uint16_t checksum16(const void *data, size_t len);

/* Fold and finalize an accumulated 32-bit checksum sum */
uint16_t checksum_fold(uint32_t sum);

#endif