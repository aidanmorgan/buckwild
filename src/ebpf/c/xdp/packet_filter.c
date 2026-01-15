#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "../include/protocol.h"
#include "../include/security.h"

char LICENSE[] SEC("license") = "GPL";

// Packet filtering logic for Buckwild protocol
SEC("xdp")
int xdp_packet_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // Basic Ethernet header validation
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    
    // Only process IP packets
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;
    
    // Basic IP header validation
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    
    // Only process UDP packets
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    // Bounds check before UDP header pointer arithmetic
    // eBPF verifier requires bounds validation before pointer arithmetic
    if ((void *)ip + (ip->ihl * 4) + sizeof(struct udphdr) > data_end)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + (ip->ihl * 4);
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;
    
    // Check if this could be a Buckwild protocol packet
    __u16 dest_port = bpf_ntohs(udp->dest);
    if (dest_port < 1024 || dest_port > 65535)
        return XDP_PASS;

    // Bounds check before payload access
    // eBPF verifier requires validation of all packet data access
    void *payload = (void *)(udp + 1);
    if (payload > data_end)
        return XDP_PASS;

    if (!is_buckwild_packet(payload, data_end))
        return XDP_PASS;
    
    // Pass to main handler
    return XDP_PASS;
}