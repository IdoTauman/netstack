#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/in.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/inetdevice.h>
#include "ip.h"
#include "udp.h"
#include "net_utils.h"

static uint16_t udp_calc_csum(struct ip_hdr *ip, uint8_t *payload, size_t udp_len) {
    struct udp_hdr *udp = (struct udp_hdr *)payload;
    struct udp_pseudo_hdr ph;
    ph.src_ip = ip->src_ip;
    ph.dst_ip = ip->dst_ip;
    ph.zero = 0;
    ph.proto = IP_PROTO_UDP;
    ph.udp_len = udp->len; /* network byte order */

    uint32_t sum = 0;

    // sum 12 byte pseudo header (6 x 16bit)
    const uint16_t *ph_ptr = (const uint16_t *)&ph;
    for (size_t i = 0; i < sizeof(struct udp_pseudo_hdr) / 2; i++) {
        sum += ph_ptr[i];
    }

    // sum udp datagram (header + data)
    const uint16_t *udp_ptr = (const uint16_t *)payload;
    size_t remaining = udp_len;
    while (remaining > 1) {
        sum += *udp_ptr++;
        remaining -= 2;
    }
    if (remaining == 1) {
        uint16_t odd_word = 0;
        *(uint8_t *)&odd_word = *(const uint8_t *)udp_ptr;
        sum += odd_word;
    }

    return checksum_fold(sum);
}

void udp_input(int tun_fd, struct ip_hdr *ip, uint8_t *payload, size_t len) {
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

    // log and echo on port 9000 for testing
    uint16_t src_p = ntohs(udp->src_port);
    uint16_t dst_p = ntohs(udp->dst_port);

    pr_info("[netstack] UDP %pI4:%u -> %pI4:%u (%zu bytes)\n",
            &ip->src_ip, src_p, &ip->dst_ip, dst_p, data_len);

    // echo on port 9000 for logging
    if (dst_p == 9000) {
        pr_info("[netstack] Echoing %zu bytes back to %pI4:%u\n", data_len, &ip->src_ip, src_p);

        udp_send(tun_fd,
                 ip->dst_ip, udp->dst_port,
                 ip->src_ip, udp->src_port,
                 udp_data, data_len);
    }
}

void udp_send(int tun_fd, uint32_t src_ip, uint16_t src_port,
              uint32_t dst_ip, uint16_t dst_port,
              const uint8_t *payload, size_t payload_len) {
    size_t ip_hlen = sizeof(struct ip_hdr);
    size_t udp_hlen = sizeof(struct udp_hdr);
    size_t udp_total_len = udp_hlen + payload_len;
    size_t total_len = ip_hlen + udp_total_len;
    struct net_device *dev;
    struct sk_buff *skb;
    uint8_t *pkt_buf;

    (void)tun_fd;

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
    ip->ihl = 5;
    ip->version = 4;
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