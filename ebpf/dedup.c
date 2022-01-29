#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>

SEC("xdp_drop")
int xdp_dedup_prog(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    __u16 h_proto;

    if (data + sizeof(struct ethhdr) > data_end)
        return XDR_DROP;
    
    h_proto = eth->h_proto;

/*
    if (h_proto == htons(ETH_P_IP6))
        return XDP_DROP;
*/
    if (h_proto == htons(ETH_P_IP4)) {
        
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "abc";
