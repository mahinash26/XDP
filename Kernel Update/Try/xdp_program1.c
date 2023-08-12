// xdp_program1.c
#include "shared_map.h"

SEC("xdp_program1")
int xdp_program1(struct __sk_buff *skb) {
    int key = 0;
    int value = 1;
    bpf_map_update_elem(&my_shared_map, &key, &value, BPF_ANY);
    return XDP_PASS;
}

