#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

struct ip_data {
    __u32 src_ip;
    __u16 src_port;
    __u32 dst_ip;
    __u16 dst_port;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, int);
    __type(value, struct ip_data);
    __uint(max_entries, 10);
} my_map SEC(".maps");

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
                int key = 0; // Index for the my_map array
                struct ip_data ip_data2 = { 0 };

                ip_data2.src_ip = ip->saddr;
                ip_data2.dst_ip = ip->daddr;
                ip_data2.src_port = tcp->source;
                ip_data2.dst_port = tcp->dest;

                bpf_map_update_elem(&my_map, &key, &ip_data2, BPF_ANY);
            } else if (ip->protocol == IPPROTO_UDP && (void *)(udp + 1) <= data_end) {
                int key = 0; // Index for the my_map array
                struct ip_data ip_data2 = { 0 };

                ip_data2.src_ip = ip->saddr;
                ip_data2.dst_ip = ip->daddr;
                ip_data2.src_port = udp->source;
                ip_data2.dst_port = udp->dest;

                bpf_map_update_elem(&my_map, &key, &ip_data2, BPF_ANY);
            }
        }
    }

out:
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";