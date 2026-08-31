#ifndef UDP_H
#define UDP_H

#include <linux/types.h>
#include "ip.h"

#define PACKET_LEN 1500

struct __attribute__((packed)) udp_hdr {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t len;        /* header + payload length */
    uint16_t csum;
};

// 12 byte ipv4 pseudo header for udp checksum calculation
struct __attribute__((packed)) udp_pseudo_hdr {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint8_t  zero;
    uint8_t  proto;      /* always 17 (0x11) */
    uint16_t udp_len;    /* matches udp_hdr.len */
};

/* Handles an incoming UDP datagram. Delivers to a bound AF_CUSTOM socket
 * if one matches (src_ip/src_port of the *sender* become the packet's
 * origin as seen by recvmsg()); falls back to the port-9000 echo test
 * if nothing is bound to the destination. */
void udp_input(struct ip_hdr *ip, uint8_t *payload, size_t len);

/* Transmits a UDP packet back through the stack */
void udp_send(uint32_t src_ip, uint16_t src_port,
              uint32_t dst_ip, uint16_t dst_port,
              const uint8_t *payload, size_t payload_len);

#endif