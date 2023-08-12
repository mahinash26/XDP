#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

#define HTTP_PORT 80

struct ip_data {
    __u32 src_ip;
    __u16 src_port;
    __u32 dst_ip;
    __u16 dst_port;
    char url[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, int);
    __type(value, struct ip_data);
    __uint(max_entries, 10);
} my_map SEC(".maps");

static __always_inline char *helper_strstr(const char *haystack, const char *needle, int haystack_len, int needle_len) {
    char c;
    int i, j;

    // Calculate haystack length
    for (i = 0; i < haystack_len; i++) {
        if (bpf_probe_read(&c, sizeof(c), (void *)(haystack + i)) != 0) {
            break;
        }
        if (c == '\0') {
            break;
        }
    }
    haystack_len = i;

    // Calculate needle length
    for (j = 0; j < needle_len; j++) {
        if (bpf_probe_read(&c, sizeof(c), (void *)(needle + j)) != 0) {
            break;
        }
        if (c == '\0') {
            break;
        }
    }
    needle_len = j;

    // Check for empty strings
    if (haystack_len == 0 || needle_len == 0) {
        return NULL;
    }

    int len_diff = haystack_len - needle_len;

    for (i = 0; i <= len_diff; i++) {
        int found = 1;
        for (j = 0; j < needle_len; j++) {
            char haystack_c;
            if (bpf_probe_read(&haystack_c, sizeof(haystack_c), (void *)(haystack + i + j)) != 0) {
                found = 0;
                break;
            }
            if (haystack_c != c) {
                found = 0;
                break;
            }
        }
        if (found) {
            return (char *)(haystack + i);
        }
    }
    return NULL;  // Return NULL if needle is not found
}

SEC("xdp")
int my_xdp_program(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    if (data + sizeof(*eth) > data_end)
        goto out;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        goto out;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end)
        goto out;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
        if ((void *)(tcp + 1) > data_end)
            goto out;

        if (tcp->dest != __constant_htons(HTTP_PORT))
            goto out;

        char *http_request = (char *)(tcp + 1);

        // Calculate the length of the TCP payload
        int tcp_payload_len = (int)((void *)data_end - (void *)http_request);

        char *url = helper_strstr(http_request, "Host:", tcp_payload_len, 255);
        if (url) {
            url += 6;
            int url_len = tcp_payload_len - (url - http_request);
            if (url_len > sizeof(struct ip_data)) {
                url_len = sizeof(struct ip_data);
            }

            struct ip_data ip_data2 = {
                .src_ip = ip->saddr,
                .src_port = tcp->source,
                .dst_ip = ip->daddr,
                .dst_port = tcp->dest,
            };

            bpf_probe_read(&ip_data2.url, url_len, url);

            int key = 0;  // Index for the my_map array
            bpf_map_update_elem(&my_map, &key, &ip_data2, BPF_ANY);
        }
    }

out:
    return XDP_PASS;
}
