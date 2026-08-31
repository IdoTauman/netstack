#ifndef CUSTOM_SOCK_H
#define CUSTOM_SOCK_H

#include <linux/types.h>
#include <linux/socket.h>

#define AF_CUSTOM          99       /* unused address family number */
#define PF_CUSTOM          AF_CUSTOM
#define SOCK_CUSTOM_DGRAM  2        /* match SOCK_DGRAM */

struct sockaddr_custom {
    __kernel_sa_family_t sc_family; /* AF_CUSTOM */
    __be16               sc_port;   /* Port in network byte order */
    __be32               sc_addr;   /* IPv4 in network byte order */
};

#endif