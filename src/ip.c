#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/in.h>
#include "ip.h"
#include "udp.h"
#include "net_utils.h"

void ip_input(uint8_t *buf, size_t len) {
    /* check size */
    if (len < sizeof(struct ip_hdr))
        return;

    /* overlay ip header struct */
    struct ip_hdr *ip = (struct ip_hdr *)buf;

    /* check ip version (ipv6 not supported) */
    if (ip->version != 4)
        return;

    /* calculate and validate internet header length (ihl) */
    size_t ip_hlen = ip->ihl * 4;
    if (ip_hlen < sizeof(struct ip_hdr) || len < ip_hlen)
        return;

    /* validate total length vs received length */
    size_t total_len = ntohs(ip->total_len);
    if (total_len < ip_hlen || len < total_len)
        return;

    /* verify ipv4 header checksum */
    uint16_t chksm = checksum16(ip, ip_hlen);
    if (chksm != 0) {
        pr_warn("[netstack] Dropping packet: invalid IP checksum\n");
        return;
    }

    /* demultiplex to layer 4 (transport protocol) */
    uint8_t *payload = buf + ip_hlen;
    size_t payload_len = total_len - ip_hlen;

    switch (ip->proto) {
        case IP_PROTO_UDP:
            udp_input(ip, payload, payload_len);
            break;
        default:
            pr_info("[netstack] Protocol %u not supported\n", ip->proto);
            break;
    }
}