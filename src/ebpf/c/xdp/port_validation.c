#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "../include/maps.h"
#include "../include/protocol.h"

char LICENSE[] SEC("license") = "GPL";

// Port hopping validation for XDP
SEC("xdp")
int xdp_port_validation(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // Parse headers
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;
    
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;
    
    struct udphdr *udp = (void *)ip + (ip->ihl * 4);
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;
    
    __u16 dest_port = bpf_ntohs(udp->dest);
    void *payload = (void *)(udp + 1);
    
    // Parse Buckwild header
    struct parsed_header parsed = {0};
    if (parse_buckwild_header(payload, data_end, &parsed) < 0)
        return XDP_DROP;
    
    // Validate port hopping for established sessions
    if (parsed.session_id != 0) {
        struct session_info *session = MAP_LOOKUP_ELEM(session_map, &parsed.session_id);
        if (session) {
            // Simple port validation - full implementation would calculate expected port
            __u32 expected_port = session->expected_port;
            __u16 port_tolerance = 10;
            
            if (dest_port < expected_port - port_tolerance ||
                dest_port > expected_port + port_tolerance) {
                return XDP_DROP; // Port outside expected range
            }
        }
    }
    
    return XDP_PASS;
}