#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

// Structure to hold IP and port data
struct ip_data {
    __u32 src_ip;
    __u16 src_port;
    __u32 dst_ip;
    __u16 dst_port;
};

// Define a hash map named "my_map" with key-value pairs
struct {
    __uint(type, BPF_MAP_TYPE_HASH); // Map type: Hash map
    __type(key, struct ip_data);      // Key type: struct ip_data
    __type(value, __u64);            // Value type: 64-bit unsigned integer (counter)
    __uint(max_entries, 10);         // Maximum number of entries in the map
} my_map SEC(".maps");               // Mark the map as a section in the ELF file

// XDP program entry point
SEC("xdp")
int my_xdp_program(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;

    if (data + sizeof(*eth) > data_end)
         goto out;

    struct iphdr *ip = (struct iphdr *)(data + sizeof(*eth));

    if ((void *)(ip + 1) > data_end)
        goto out;

    if (eth->h_proto == __constant_htons(ETH_P_IP)) {
        if ((void *)(ip + 1 + 1) <= data_end) { // Ensure enough space for IP header and protocol
            struct tcphdr *tcp = (struct tcphdr *)((void *)ip + sizeof(struct iphdr));
            struct udphdr *udp = (struct udphdr *)((void *)ip + sizeof(struct iphdr));

            if (ip->protocol == IPPROTO_TCP && (void *)(tcp + 1) <= data_end) {
                struct ip_data ip_data2 = { 0 };

                ip_data2.src_ip = ip->saddr;
                ip_data2.dst_ip = ip->daddr;
                ip_data2.src_port = tcp->source;
                ip_data2.dst_port = tcp->dest;

                __u64 *value = bpf_map_lookup_elem(&my_map, &ip_data2);
                if (value) {
                    (*value)++; // Increment the counter value if key exists
                } else {
                    __u64 count = 1;
                    bpf_map_update_elem(&my_map, &ip_data2, &count, BPF_ANY);
                }
            } else if (ip->protocol == IPPROTO_UDP && (void *)(udp + 1) <= data_end) {
                struct ip_data ip_data2 = { 0 };

                ip_data2.src_ip = ip->saddr;
                ip_data2.dst_ip = ip->daddr;
                ip_data2.src_port = udp->source;
                ip_data2.dst_port = udp->dest;

                __u64 *value = bpf_map_lookup_elem(&my_map, &ip_data2);
                if (value) {
                    (*value)++; // Increment the counter value if key exists
                } else {
                    __u64 count = 1;
                    bpf_map_update_elem(&my_map, &ip_data2, &count, BPF_ANY);
                }
            }
        }
    }

out:
    return XDP_PASS; // Allow the packet to pass through
}

// Define the license for the BPF program
char _license[] SEC("license") = "GPL";

/*
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

// Structure to hold IP and port data
struct ip_data {
    __u32 src_ip;
    __u16 src_port;
    __u32 dst_ip;
    __u16 dst_port;
};

// Define a hash map named "my_map" with key-value pairs
struct {
    __uint(type, BPF_MAP_TYPE_HASH); // Map type: Hash map
    __type(key, struct ip_data);      // Key type: struct ip_data
    __type(value, __u64);            // Value type: 64-bit unsigned integer (counter)
    __uint(max_entries, 10);         // Maximum number of entries in the map
} my_map SEC(".maps");               // Mark the map as a section in the ELF file

// XDP program entry point
SEC("xdp")
int my_xdp_program(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;

    if (data + sizeof(*eth) > data_end)
         goto out;

    struct iphdr *ip = (struct iphdr *)(data + sizeof(*eth));

    if ((void *)(ip + 1) > data_end)
        goto out;

    if (eth->h_proto == __constant_htons(ETH_P_IP)) {
        if ((void *)(ip + 1 + 1) <= data_end) { // Ensure enough space for IP header and protocol
            struct tcphdr *tcp = (struct tcphdr *)((void *)ip + sizeof(struct iphdr));
            struct udphdr *udp = (struct udphdr *)((void *)ip + sizeof(struct iphdr));

            if (ip->protocol == IPPROTO_TCP && (void *)(tcp + 1) <= data_end) {
                struct ip_data ip_data2 = { 0 };

                ip_data2.src_ip = ip->saddr;
                ip_data2.dst_ip = ip->daddr;
                ip_data2.src_port = tcp->source;
                ip_data2.dst_port = tcp->dest;

                __u64 *value = bpf_map_lookup_elem(&my_map, &ip_data2);
                if (value) {
                    (*value)++; // Increment the counter value if key exists
                } else {
                    __u64 count = 1;
                    bpf_map_update_elem(&my_map, &ip_data2, &count, BPF_ANY);
                }
            } else if (ip->protocol == IPPROTO_UDP && (void *)(udp + 1) <= data_end) {
                struct ip_data ip_data2 = { 0 };

                ip_data2.src_ip = ip->saddr;
                ip_data2.dst_ip = ip->daddr;
                ip_data2.src_port = udp->source;
                ip_data2.dst_port = udp->dest;

                __u64 *value = bpf_map_lookup_elem(&my_map, &ip_data2);
                if (value) {
                    (*value)++; // Increment the counter value if key exists
                } else {
                    __u64 count = 1;
                    bpf_map_update_elem(&my_map, &ip_data2, &count, BPF_ANY);
                }
            }
        }
    }

out:
    return XDP_PASS; // Allow the packet to pass through
}

// Define the license for the BPF program
char _license[] SEC("license") = "GPL";
*/