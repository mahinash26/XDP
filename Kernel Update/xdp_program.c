#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

// Define the map structure for the XDP program
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 10); // Increase max_entries to allow more elements
    __type(key, int);
    __type(value, int);
} my_map SEC(".maps");

SEC("xdp") // Add the SEC identifier for XDP program
int my_xdp_program(struct __sk_buff *skb) {
    int key;
    int value;

    // Element 0: Set value to 42
    key = 0;
    value = 42;
    bpf_map_update_elem(&my_map, &key, &value, BPF_ANY);

    // Element 1: Set value to 100
    key = 1;
    value = 100;
    bpf_map_update_elem(&my_map, &key, &value, BPF_ANY);

    // Element 2: Set value to 55
    key = 2;
    value = 55;
    bpf_map_update_elem(&my_map, &key, &value, BPF_ANY);

    // Element 3: Set value to 123
    key = 3;
    value = 123;
    bpf_map_update_elem(&my_map, &key, &value, BPF_ANY);

    // ... and so on for the other elements

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

