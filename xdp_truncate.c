#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <arpa/inet.h>

/*
 * Truncate packets after the headers, removing any payload.
 * Unknown protocols will be passed through without modification.
 *
 * Enable:
 *   sudo ip link set dev eth0 xdp object xdp_truncate.o section truncate
 * Disable:
 *   sudo ip link set dev eth0 xdp off
 */

SEC("truncate")
int xdp_truncate(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth;

    int protocol;
    int total_len;
    int eth_len = ETH_HLEN;
    int ip_len = 0;
    int l4_len = 0;
    int snap_len = 0;

    eth = data;
    if (eth + 1 > data_end) {
        return XDP_PASS;
    }

    /* determine length of ip header */
    switch (bpf_ntohs(eth->h_proto)) {
        case ETH_P_IP: {
            struct iphdr *ip;
            /* TODO: do we need to check ip version despite the ethertype? */
            ip = (struct iphdr*)(data + eth_len);
            if (ip + 1 > data_end) {
                return XDP_PASS;
            }
            ip_len = ip->ihl * 4;
            protocol = ip->protocol;
            break;
        }
        case ETH_P_IPV6: {
            struct ipv6hdr *ipv6;
            /* TODO: do we need to check ip version despite the ethertype? */
            ipv6 = (struct ipv6hdr*)(data + eth_len);
            if (ipv6 + 1 > data_end) {
                return XDP_PASS;
            }
            /* TODO: update length to skip non-protocol next headers */
            ip_len = sizeof(struct ipv6hdr);
            protocol = ipv6->nexthdr;
            break;
        }
        default: {
            return XDP_PASS;
        }
    };

    /* determine length of transport header */
    switch (protocol) {
        case IPPROTO_ICMPV6:
            /* fall through to ICMPv4 as the headers are the same size */
        case IPPROTO_ICMP: {
            /* TODO: do we want any more of the icmp payload? */
            l4_len = sizeof(struct icmphdr);
            break;
        }
        case IPPROTO_UDP: {
            l4_len = sizeof(struct udphdr);
            break;
        }
        case IPPROTO_TCP: {
            struct tcphdr *tcp;
            tcp = (struct tcphdr*)(data + eth_len + ip_len);
            if (tcp + 1 > data_end) {
                return XDP_PASS;
            }
            l4_len = tcp->doff * 4;
            break;
        }
        default: {
            /* TODO: other protocols */
            return XDP_PASS;
        }
    };

    /* determine combined length of all headers */
    snap_len = eth_len + ip_len + l4_len;
    if (data + snap_len > data_end) {
        return XDP_PASS;
    }

    /* truncate packet after headers, before payload */
    total_len = data_end - data;
    if (bpf_xdp_adjust_tail(ctx, snap_len - total_len)) {
        /* TODO: what to do if resize fails? */
        return XDP_PASS;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
