#ifndef UDP_H
#define UDP_H

#include <linux/types.h>
#include <stddef.h>
#include "ip.h"

#define PACKET_LEN 1500

struct __attribute__((packed)) udp_hdr {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t len;        /* Header + payload length */
    uint16_t csum;
};

/* 12-byte IPv4 Pseudo-Header for UDP Checksum Calculation (RFC 768) */
struct __attribute__((packed)) udp_pseudo_hdr {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint8_t  zero;
    uint8_t  proto;      /* Always 17 (0x11) */
    uint16_t udp_len;    /* Matches udp_hdr.len */
};

/* Handles an incoming UDP datagram */
void udp_input(int tun_fd, struct ip_hdr *ip, uint8_t *payload, size_t len);

/* Transmits a UDP packet back through the stack */
void udp_send(int tun_fd, uint32_t src_ip, uint16_t src_port,
              uint32_t dst_ip, uint16_t dst_port,
              const uint8_t *payload, size_t payload_len);

#endif