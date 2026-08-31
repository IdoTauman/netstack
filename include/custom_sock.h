#ifndef CUSTOM_SOCK_H
#define CUSTOM_SOCK_H

#include <linux/types.h>
#include <linux/socket.h>

#define AF_CUSTOM          45
#define PF_CUSTOM          AF_CUSTOM
#define SOCK_CUSTOM_DGRAM  2

struct sockaddr_custom {
    __kernel_sa_family_t sc_family;
    __be16               sc_port;
    __be32               sc_addr;
};

int custom_sock_init(void);
void custom_sock_exit(void);

#endif