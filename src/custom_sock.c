#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/if_ether.h>
#include <net/sock.h>
#include <linux/spinlock.h>
#include "custom_sock.h"
#include "ip.h"
#include "udp.h"

// per socket state (persists between syscalls)
struct custom_sock_data {
    __be16 bound_port;
    __be32 bound_ip;
    // bind list
    struct sock *sk;
    struct list_head node;
};

// control block stashed in the cb[] area of skbs queued on a socket's
// receive queue, so recvmsg() can report where a datagram came from.
struct custom_recv_cb {
    __be32 addr;
    __be16 port;
};

// global head and sync lock
static LIST_HEAD(custom_bound_sockets);
static DEFINE_SPINLOCK(custom_bind_lock);

// net device we listen for inbound IP packets on (loopback, since that's
// the only interface udp_send() currently transmits on)
static struct net_device *netstack_rx_dev;

#define EPHEMERAL_PORT_MIN 49152
#define EPHEMERAL_PORT_MAX 65535

// rotate through ephemeral ports round robin
static uint16_t last_ephemeral_port = EPHEMERAL_PORT_MIN;

static int custom_autobind(struct sock *sk) {
    struct custom_sock_data *priv = (struct custom_sock_data *)sk->sk_user_data;
    struct custom_sock_data *entry;
    unsigned long flags;
    uint16_t candidate_port;
    bool in_use;
    int attempts = 0;
    int max_attempts = EPHEMERAL_PORT_MAX - EPHEMERAL_PORT_MIN + 1;

    spin_lock_irqsave(&custom_bind_lock, flags);

    // check again under lock in case another thread bound it
    if (priv->bound_port != 0) {
        spin_unlock_irqrestore(&custom_bind_lock, flags);
        return 0;
    }

    while (attempts < max_attempts) {
        candidate_port = last_ephemeral_port++;
        if (last_ephemeral_port > EPHEMERAL_PORT_MAX) {
            last_ephemeral_port = EPHEMERAL_PORT_MIN;
        }

        __be16 port_be = htons(candidate_port);
        in_use = false;

        // Check if port is taken
        list_for_each_entry(entry, &custom_bound_sockets, node) {
            if (entry->bound_port == port_be) {
                in_use = true;
                break;
            }
        }

        if (!in_use) {
            // found open ephemeral port
            priv->bound_port = port_be;
            priv->bound_ip   = 0; /* INADDR_ANY */
            priv->sk         = sk;
            list_add_tail(&priv->node, &custom_bound_sockets);

            spin_unlock_irqrestore(&custom_bind_lock, flags);
            pr_info("[custom_sock] Auto-bound unbound socket to ephemeral port %u\n", candidate_port);
            return 0;
        }

        attempts++;
    }

    spin_unlock_irqrestore(&custom_bind_lock, flags);
    return -EADDRNOTAVAIL; /* all ephemeral ports in use */
}

// socket release (close)
static int custom_release(struct socket *sock) {
    struct sock *sk = sock->sk;
    struct custom_sock_data *priv;
    unsigned long flags;

    if (sk) {
        priv = (struct custom_sock_data *)sk->sk_user_data;
        if (priv) {
            spin_lock_irqsave(&custom_bind_lock, flags);
            if (priv->bound_port != 0) {
                list_del(&priv->node);
            }
            spin_unlock_irqrestore(&custom_bind_lock, flags);

            kfree(priv);
            sk->sk_user_data = NULL;
        }

        skb_queue_purge(&sk->sk_receive_queue);
        sock_orphan(sk);
        sock_put(sk);
    }
    return 0;
}

// bind operation
static int custom_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len) {
    struct sockaddr_custom *addr = (struct sockaddr_custom *)uaddr;
    struct custom_sock_data *priv, *entry;
    unsigned long flags;

    if (addr_len < sizeof(struct sockaddr_custom))
        return -EINVAL;

    if (addr->sc_family != AF_CUSTOM)
        return -EAFNOSUPPORT;

    priv = (struct custom_sock_data *)sock->sk->sk_user_data;

    spin_lock_irqsave(&custom_bind_lock, flags);

    // prevent double binding
    if (priv->bound_port != 0) {
        spin_unlock_irqrestore(&custom_bind_lock, flags);
        return -EINVAL;
    }

    // check for port collision
    list_for_each_entry(entry, &custom_bound_sockets, node) {
        if (entry->bound_port == addr->sc_port) {
            // if ip is INADDR_ANY (0.0.0.0) or ips match exactly the port is busy
            if (entry->bound_ip == 0 || addr->sc_addr == 0 || entry->bound_ip == addr->sc_addr) {
                spin_unlock_irqrestore(&custom_bind_lock, flags);
                return -EADDRINUSE;
            }
        }
    }

    // bind and update global list
    priv->bound_port = addr->sc_port;
    priv->bound_ip   = addr->sc_addr;
    priv->sk = sock->sk;
    list_add_tail(&priv->node, &custom_bound_sockets);

    spin_unlock_irqrestore(&custom_bind_lock, flags);

    pr_info("[custom_sock] Socket bound to %pI4:%u\n",
            &priv->bound_ip, ntohs(priv->bound_port));

    return 0;
}

// sendmsg operation (copies to kernel space and forwards to udp_send())
static int custom_sendmsg(struct socket *sock, struct msghdr *msg, size_t len) {
    struct sockaddr_custom *dst = (struct sockaddr_custom *)msg->msg_name;
    struct custom_sock_data *priv = (struct custom_sock_data *)sock->sk->sk_user_data;
    uint8_t *kbuf;
    int err;

    if (!dst || msg->msg_namelen < sizeof(struct sockaddr_custom))
        return -EDESTADDRREQ;

    if (len > PACKET_LEN)
        return -EMSGSIZE;

    if (priv->bound_port == 0) {
        err = custom_autobind(sock->sk);
        if (err) return err;
    }

    kbuf = kmalloc(len, GFP_KERNEL);
    if (!kbuf)
        return -ENOMEM;

    err = copy_from_iter(kbuf, len, &msg->msg_iter);
    if (err != len) {
        kfree(kbuf);
        return -EFAULT;
    }

    pr_info("[custom_sock] sendmsg: %zu bytes -> %pI4:%u\n",
            len, &dst->sc_addr, ntohs(dst->sc_port));

    udp_send(priv->bound_ip, priv->bound_port,
             dst->sc_addr, dst->sc_port,
             kbuf, len);

    kfree(kbuf);
    return len;
}

// recvmsg operation: pop the next datagram queued for this socket by
// udp_input() -> custom_sock_deliver()
static int custom_recvmsg(struct socket *sock, struct msghdr *msg, size_t len, int flags) {
    struct sock *sk = sock->sk;
    struct sk_buff *skb;
    struct custom_recv_cb *cb;
    int copied, err;

    skb = skb_recv_datagram(sk, flags, &err);
    if (!skb)
        return err;

    copied = skb->len;
    if (copied > len) {
        copied = len;
        msg->msg_flags |= MSG_TRUNC;
    }

    err = skb_copy_datagram_msg(skb, 0, msg, copied);
    if (err) {
        skb_free_datagram(sk, skb);
        return err;
    }

    if (msg->msg_name) {
        struct sockaddr_custom *sc = (struct sockaddr_custom *)msg->msg_name;

        cb = (struct custom_recv_cb *)skb->cb;
        memset(sc, 0, sizeof(*sc));
        sc->sc_family = AF_CUSTOM;
        sc->sc_port   = cb->port;
        sc->sc_addr   = cb->addr;
        msg->msg_namelen = sizeof(*sc);
    }

    skb_free_datagram(sk, skb);
    return copied;
}

// looks up a socket bound to (local_ip, local_port); local_ip == 0 on the
// bound socket means it was bound to INADDR_ANY and matches any address
struct sock *custom_sock_lookup(__be32 local_ip, __be16 local_port) {
    struct custom_sock_data *entry;
    struct sock *found = NULL;
    unsigned long flags;

    spin_lock_irqsave(&custom_bind_lock, flags);
    list_for_each_entry(entry, &custom_bound_sockets, node) {
        if (entry->bound_port == local_port &&
            (entry->bound_ip == 0 || entry->bound_ip == local_ip)) {
            found = entry->sk;
            sock_hold(found);
            break;
        }
    }
    spin_unlock_irqrestore(&custom_bind_lock, flags);

    return found;
}

void custom_sock_deliver(struct sock *sk, __be32 src_ip, __be16 src_port,
                          const uint8_t *data, size_t len) {
    struct sk_buff *skb;
    struct custom_recv_cb *cb;

    skb = alloc_skb(len, GFP_ATOMIC);
    if (!skb) {
        pr_warn("[custom_sock] Failed to allocate skb for delivery\n");
        return;
    }

    if (len > 0)
        skb_put_data(skb, data, len);

    cb = (struct custom_recv_cb *)skb->cb;
    cb->addr = src_ip;
    cb->port = src_port;

    if (sock_queue_rcv_skb(sk, skb) < 0) {
        pr_warn("[custom_sock] Receive queue full, dropping datagram\n");
        kfree_skb(skb);
    }
}

// Inbound packet hook: registered for ETH_P_IP on the loopback device
// only (see netstack_rx_dev). This is what actually feeds packets into
// ip_input()/udp_input() -- without it those functions were dead code.
static int netstack_rx_handler(struct sk_buff *skb, struct net_device *dev,
                                struct packet_type *pt, struct net_device *orig_dev) {
    skb = skb_share_check(skb, GFP_ATOMIC);
    if (!skb)
        return NET_RX_DROP;

    if (!pskb_may_pull(skb, sizeof(struct ip_hdr))) {
        kfree_skb(skb);
        return NET_RX_DROP;
    }

    ip_input(skb->data, skb->len);

    kfree_skb(skb);
    return NET_RX_SUCCESS;
}

static struct packet_type netstack_pt = {
    .type = 0, /* set at init to cpu_to_be16(ETH_P_IP) */
    .func = netstack_rx_handler,
};

// protocol operations table
static const struct proto_ops custom_proto_ops = {
    .family     = PF_CUSTOM,
    .owner      = THIS_MODULE,
    .release    = custom_release,
    .bind       = custom_bind,
    .sendmsg    = custom_sendmsg,
    .recvmsg    = custom_recvmsg,
};

static struct proto custom_proto = {
    .name       = "CUSTOM_DGRAM",
    .owner      = THIS_MODULE,
    .obj_size   = sizeof(struct sock),
};

// socket factory callback
static int custom_sock_create(struct net *net, struct socket *sock, int protocol, int kern) {
    struct sock *sk;
    struct custom_sock_data *priv;

    if (sock->type != SOCK_CUSTOM_DGRAM && sock->type != SOCK_DGRAM)
        return -ESOCKTNOSUPPORT;

    sock->ops = &custom_proto_ops;

    sk = sk_alloc(net, PF_CUSTOM, GFP_KERNEL, &custom_proto, kern);
    if (!sk)
        return -ENOMEM;

    sock_init_data(sock, sk);

    // allocate custom socket private state
    priv = kzalloc(sizeof(struct custom_sock_data), GFP_KERNEL);
    if (!priv) {
        sk_free(sk);
        return -ENOMEM;
    }
    sk->sk_user_data = priv;

    return 0;
}

static const struct net_proto_family custom_family_ops = {
    .family = PF_CUSTOM,
    .create = custom_sock_create,
    .owner  = THIS_MODULE,
};

// registration and teardown helpers
int custom_sock_init(void) {
    int rc = proto_register(&custom_proto, 1);
    if (rc) return rc;

    rc = sock_register(&custom_family_ops);
    if (rc) {
        proto_unregister(&custom_proto);
        return rc;
    }

    // Hook inbound IP traffic on "lo" so packets udp_send() transmits
    // (and, in principle, any other IP traffic arriving on lo) get
    // demuxed back through ip_input()/udp_input() to a bound socket.
    netstack_rx_dev = dev_get_by_name(&init_net, "lo");
    if (!netstack_rx_dev) {
        pr_err("[custom_sock] Could not find loopback device for RX hook\n");
        sock_unregister(PF_CUSTOM);
        proto_unregister(&custom_proto);
        return -ENODEV;
    }

    netstack_pt.type = cpu_to_be16(ETH_P_IP);
    netstack_pt.dev  = netstack_rx_dev;
    dev_add_pack(&netstack_pt);

    pr_info("[custom_sock] Registered AF_CUSTOM protocol family (%d)\n", AF_CUSTOM);
    return 0;
}

void custom_sock_exit(void) {
    struct custom_sock_data *entry, *tmp;
    unsigned long flags;

    dev_remove_pack(&netstack_pt);
    if (netstack_rx_dev) {
        dev_put(netstack_rx_dev);
        netstack_rx_dev = NULL;
    }

    // unregister from kernel network switchboard
    sock_unregister(PF_CUSTOM);
    proto_unregister(&custom_proto);

    // flush lingering bound sockets
    spin_lock_irqsave(&custom_bind_lock, flags);
    list_for_each_entry_safe(entry, tmp, &custom_bound_sockets, node) {
        list_del(&entry->node);
        if (entry->sk) {
            entry->sk->sk_user_data = NULL;
        }
        kfree(entry);
    }
    spin_unlock_irqrestore(&custom_bind_lock, flags);

    pr_info("[custom_sock] Unregistered AF_CUSTOM and cleaned up bind table\n");
}