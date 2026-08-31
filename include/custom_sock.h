#ifndef CUSTOM_SOCK_H
#define CUSTOM_SOCK_H

#include <linux/types.h>
#include <linux/socket.h>

/* NOTE: this must not collide with an address family already assigned in
 * include/linux/socket.h on the target kernel (e.g. AF_MCTP == 45 on
 * kernel 5.15+). Check your kernel headers before loading this module.
 * Override without editing this file via:
 *   make EXTRA_CFLAGS=-DAF_CUSTOM=<unused number>
 */
#ifndef AF_CUSTOM
#define AF_CUSTOM          45
#endif
#define PF_CUSTOM          AF_CUSTOM
#define SOCK_CUSTOM_DGRAM  2

struct sockaddr_custom {
    __kernel_sa_family_t sc_family;
    __be16               sc_port;
    __be32               sc_addr;
};

int custom_sock_init(void);
void custom_sock_exit(void);

/* Looks up a socket bound to (local_ip, local_port). local_ip may be
 * INADDR_ANY-bound (matches any). Returns the socket with an extra
 * reference held (caller must sock_put()), or NULL if none is bound. */
struct sock *custom_sock_lookup(__be32 local_ip, __be16 local_port);

/* Queues a received UDP payload onto a socket's receive queue so a
 * subsequent recvmsg() call can pick it up. */
void custom_sock_deliver(struct sock *sk, __be32 src_ip, __be16 src_port,
                          const uint8_t *data, size_t len);

#endif