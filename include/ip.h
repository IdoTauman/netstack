#ifndef IP_H
#define IP_H

#include <linux/types.h>

#define IP_PROTO_UDP 17
#define NETSTACK_TTL_DEFAULT 64

struct __attribute__((packed)) ip_hdr {
    uint8_t  ihl:4, version:4;
    uint8_t  tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  proto;
    uint16_t csum;
    uint32_t src_ip;
    uint32_t dst_ip;
};

/* Parses incoming buffer, verifies header/checksum, and demuxes to L4 */
void ip_input(uint8_t *buf, size_t len);

#endif