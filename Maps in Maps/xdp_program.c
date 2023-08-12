/*#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

// Define the map structure for the XDP program
struct inner_map {
        __uint(type, BPF_MAP_TYPE_DEVMAP);
        __uint(max_entries, 10);
        __type(key, __u32);
        __type(value, __u32);
} inner_map1 SEC(".maps"), inner_map2 SEC(".maps") , inner_map3 SEC(".maps");;

struct {
        __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
        __uint(max_entries, 3);
        __type(key, __u32);
        __array(values, struct inner_map);
} outer_map SEC(".maps") = {
        .values = { &inner_map1,
                    &inner_map2,
                    &inner_map3 }
};

SEC("xdp") // Add the SEC identifier for XDP program
int my_xdp_program(struct __sk_buff *skb) {
  
    key = 0;
    value = 123;
    bpf_map_update_elem(&outer_map, &key, &value, BPF_ANY);


    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";*/

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>

// Define the inner map structure
/*struct inner_map {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10);
    __type(key, __u32);
    __type(value, __u32);
};

// Define the outer map structure
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, 2);
    __type(key, __u32);
    __array(values, struct inner_map);
} outer_map SEC(".maps");

// Initialize the inner maps as global variables
struct inner_map inner_map1 SEC(".maps");
struct inner_map inner_map2 SEC(".maps");*/

struct inner_map {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __uint(max_entries, 10);
        __type(key, __u32);
        __type(value, __u32);
} inner_map1 SEC(".maps"), inner_map2 SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
        __uint(max_entries, 2);
        __type(key, __u32);
        __array(values, struct inner_map);
} outer_map SEC(".maps") = {
        .values = { &inner_map1,
                    &inner_map2 }
};

SEC("xdp")
int my_ebpf_prog(struct __sk_buff *skb) {
    __u32 some_key_outer;
    __u32 some_key;
    __u32 new_value;

    some_key_outer = 0;
    // Get a pointer to the inner map for modification
    struct inner_map *inner_map_ptr1 = bpf_map_lookup_elem(&outer_map, &some_key_outer);
    if (!inner_map_ptr1) {
        return XDP_DROP; // Inner map not found
    }

    some_key = 0;
    new_value = 123;
    // Update the value of the inner map entry for the given key
    bpf_map_update_elem(inner_map_ptr1, &some_key, &new_value, BPF_ANY);


    some_key = 1;
    new_value = 758;
    // Update the value of the inner map entry for the given key
    bpf_map_update_elem(inner_map_ptr1, &some_key, &new_value, BPF_ANY);

    some_key_outer = 1;
    struct inner_map *inner_map_ptr2 = bpf_map_lookup_elem(&outer_map, &some_key);
    if (!inner_map_ptr2) {
        return XDP_DROP; // Inner map not found
    }

    some_key = 0;
    new_value = 12;
    // Update the value of the inner map entry for the given key
    bpf_map_update_elem(inner_map_ptr2, &some_key, &new_value, BPF_ANY);


    some_key = 1;
    new_value = 2646;
    // Update the value of the inner map entry for the given key
    bpf_map_update_elem(inner_map_ptr2, &some_key, &new_value, BPF_ANY);


    return XDP_PASS; // Pass the packet through
}
