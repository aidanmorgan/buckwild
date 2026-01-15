#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "../include/maps.h"
#include "../include/protocol.h"

char LICENSE[] SEC("license") = "GPL";

// Session lookup and validation for XDP
SEC("xdp")
int xdp_session_lookup(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // Parse headers to get to payload
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
    
    void *payload = (void *)(udp + 1);
    
    // Parse Buckwild header to get session ID
    struct parsed_header parsed = {0};
    if (parse_buckwild_header(payload, data_end, &parsed) < 0)
        return XDP_DROP;
    
    // Look up session information
    struct session_info *session = MAP_LOOKUP_ELEM(session_map, &parsed.session_id);
    if (!session) {
        // Unknown session - could be new connection
        return XDP_PASS; // Let userspace handle
    }
    
    // Validate session binding
    __u32 src_ip = ip->saddr;
    __u16 src_port = bpf_ntohs(udp->source);
    
    if (session->src_ip != src_ip || session->src_port != src_port) {
        // Potential session hijacking
        return XDP_DROP;
    }
    
    // Update session activity
    session->last_packet_time = bpf_ktime_get_ns();
    session->packet_count++;
    MAP_UPDATE_ELEM(session_map, &parsed.session_id, session, BPF_ANY);
    
    return XDP_PASS;
}