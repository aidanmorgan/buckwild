#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "../include/maps.h"
#include "../include/protocol.h"

char LICENSE[] SEC("license") = "GPL";

// Session-based socket filtering
SEC("socket")
int socket_session_filter(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    
    // Parse headers to get to payload
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return 0; // Drop
    
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return 0; // Drop
    
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return 0; // Drop
    
    if (ip->protocol != IPPROTO_UDP)
        return 0; // Drop
    
    struct udphdr *udp = (void *)ip + (ip->ihl * 4);
    if ((void *)(udp + 1) > data_end)
        return 0; // Drop
    
    void *payload = (void *)(udp + 1);
    
    // Check if this is a Buckwild protocol packet
    if (!is_buckwild_packet(payload, data_end))
        return 0; // Drop
    
    // Parse header to get session ID
    struct parsed_header parsed = {0};
    if (parse_buckwild_header(payload, data_end, &parsed) < 0)
        return 0; // Drop
    
    // Check if session exists
    if (parsed.session_id != 0) {
        struct session_info *session = MAP_LOOKUP_ELEM(session_map, &parsed.session_id);
        if (!session)
            return 0; // Drop - unknown session
    }
    
    return skb->len; // Accept
}