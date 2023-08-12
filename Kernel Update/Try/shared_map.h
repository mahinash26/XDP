#include <linux/bpf.h>

// Define the BPF map
struct bpf_map_def SEC("maps") xdp_stats_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(int),
    .max_entries = 1,
};

