// xdp_program2.c
#include "shared_map.h"

SEC("xdp_program2")
int xdp_program2(struct __sk_buff *skb) {
    int key = 0;
    int value = 0;
    bpf_map_lookup_elem(&my_shared_map, &key, &value);
    if (value != 0) {
        // Modify packet handling logic based on the shared map value
        // For example, drop the packet if the value is 1
        return XDP_DROP;
    }
    return XDP_PASS;
}

