#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/in.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/inetdevice.h>
#include <net/sock.h>
#include "ip.h"
#include "udp.h"
#include "net_utils.h"
#include "custom_sock.h"

static uint16_t udp_calc_csum(struct ip_hdr *ip, uint8_t *payload, size_t udp_len) {
    struct udp_hdr *udp = (struct udp_hdr *)payload;
    struct udp_pseudo_hdr ph;
    ph.src_ip = ip->src_ip;
    ph.dst_ip = ip->dst_ip;
    ph.zero = 0;
    ph.proto = IP_PROTO_UDP;
    ph.udp_len = udp->len; /* network byte order */

    uint32_t sum = 0;

    // sum 12 byte pseudo header (6 x 16bit) -- ph is a local, naturally
    // aligned struct so a direct 16-bit read is safe here.
    const uint16_t *ph_ptr = (const uint16_t *)&ph;
    for (size_t i = 0; i < sizeof(struct udp_pseudo_hdr) / 2; i++) {
        sum += ph_ptr[i];
    }

    // sum udp datagram (header + data). `payload` comes from a packet
    // buffer with no alignment guarantee, so read via memcpy rather than
    // dereferencing a uint16_t* directly.
    size_t i = 0;
    while (i + 1 < udp_len) {
        uint16_t word;
        memcpy(&word, payload + i, sizeof(word));
        sum += word;
        i += 2;
    }
    if (i < udp_len) {
        uint16_t odd_word = 0;
        ((uint8_t *)&odd_word)[0] = payload[i];
        sum += odd_word;
    }

    return checksum_fold(sum);
}

void udp_input(struct ip_hdr *ip, uint8_t *payload, size_t len) {
    // udp header length check
    if (len < sizeof(struct udp_hdr)) return;

    // overlay udp header struct
    struct udp_hdr *udp = (struct udp_hdr *)payload;

    // length field validation
    size_t udp_len = ntohs(udp->len);
    if (udp_len < sizeof(struct udp_hdr) || len < udp_len) return;

    // extract payload data and length
    uint8_t *udp_data = payload + sizeof(struct udp_hdr);
    size_t data_len = udp_len - sizeof(struct udp_hdr);

    // validate udp checksum
    if (udp->csum != 0) {
        if (udp_calc_csum(ip, payload, udp_len) != 0) {
            pr_warn("[netstack] Dropping packet: invalid UDP checksum\n");
            return;
        }
    }

    uint16_t src_p = ntohs(udp->src_port);
    uint16_t dst_p = ntohs(udp->dst_port);

    pr_info("[netstack] UDP %pI4:%u -> %pI4:%u (%zu bytes)\n",
            &ip->src_ip, src_p, &ip->dst_ip, dst_p, data_len);

    // deliver to a bound AF_CUSTOM socket, if one is listening on the
    // destination address/port
    struct sock *sk = custom_sock_lookup(ip->dst_ip, udp->dst_port);
    if (sk) {
        custom_sock_deliver(sk, ip->src_ip, udp->src_port, udp_data, data_len);
        sock_put(sk);
        return;
    }

    // no socket bound: keep the port-9000 echo for standalone testing
    // without a userspace AF_CUSTOM client
    if (dst_p == 9000) {
        pr_info("[netstack] Echoing %zu bytes back to %pI4:%u\n", data_len, &ip->src_ip, src_p);

        udp_send(ip->dst_ip, udp->dst_port,
                 ip->src_ip, udp->src_port,
                 udp_data, data_len);
    }
}

void udp_send(uint32_t src_ip, uint16_t src_port,
              uint32_t dst_ip, uint16_t dst_port,
              const uint8_t *payload, size_t payload_len) {
    size_t ip_hlen = sizeof(struct ip_hdr);
    size_t udp_hlen = sizeof(struct udp_hdr);
    size_t udp_total_len = udp_hlen + payload_len;
    size_t total_len = ip_hlen + udp_total_len;
    struct net_device *dev;
    struct sk_buff *skb;
    uint8_t *pkt_buf;

    if (total_len > PACKET_LEN) {
        pr_warn("[netstack] Packet length %zu exceeds MTU\n", total_len);
        return;
    }

    dev = dev_get_by_name(&init_net, "lo");
    if (!dev) {
        pr_err("[netstack] Failed to find network interface\n");
        return;
    }

    skb = alloc_skb(total_len + LL_RESERVED_SPACE(dev), GFP_ATOMIC);
    if (!skb) {
        dev_put(dev);
        pr_err("[netstack] Failed to allocate sk_buff\n");
        return;
    }

    skb_reserve(skb, LL_RESERVED_SPACE(dev));
    skb_reset_network_header(skb);
    pkt_buf = skb_put(skb, total_len);

    struct ip_hdr *ip = (struct ip_hdr *)pkt_buf;
    struct udp_hdr *udp = (struct udp_hdr *)(pkt_buf + ip_hlen);
    uint8_t *data = pkt_buf + ip_hlen + udp_hlen;

    if (payload && payload_len > 0) {
        memcpy(data, payload, payload_len);
    }

    // udp header
    udp->src_port = src_port;
    udp->dst_port = dst_port;
    udp->len = htons(udp_total_len);
    udp->csum = 0;

    // ip header
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->id = htons(1);
    ip->frag_off = 0;
    ip->ttl = NETSTACK_TTL_DEFAULT;
    ip->proto = IP_PROTO_UDP;
    ip->src_ip = src_ip;
    ip->dst_ip = dst_ip;
    ip->total_len = htons(total_len);
    ip->csum = 0;

    // checksums
    uint16_t u_csum = udp_calc_csum(ip, (uint8_t *)udp, udp_total_len);
    udp->csum = (u_csum == 0) ? 0xFFFF : u_csum;
    ip->csum = checksum16(ip, ip_hlen);

    // Prepend a link-layer header if the device needs one. This is a
    // no-op on "lo" (loopback has no header_ops), but keeps udp_send()
    // correct if it's ever pointed at a real interface.
    if (dev_hard_header(skb, dev, ETH_P_IP, dev->broadcast, NULL, total_len) < 0) {
        pr_warn("[netstack] dev_hard_header failed, sending without link header\n");
    }

    skb->dev = dev;
    skb->protocol = htons(ETH_P_IP);
    skb->pkt_type = PACKET_OUTGOING;

    if (dev_queue_xmit(skb) < 0) {
        pr_warn("[netstack] dev_queue_xmit failed to transmit packet\n");
    } else {
        pr_info("[netstack] Transmitted %zu bytes via %s\n", total_len, dev->name);
    }

    dev_put(dev);
}