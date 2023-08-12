#include <stdio.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <arpa/inet.h> // For inet_ntop function

#define MAP_PATH "/sys/fs/bpf/my_map"

struct ip_data {
    __u32 src_ip;
    __u16 src_port;
    __u32 dst_ip;
    __u16 dst_port;
};

int main() {
    int map_fd;
    __u32 key;
    struct ip_data value;

    // Open the BPF map
    map_fd = bpf_obj_get(MAP_PATH);
    if (map_fd < 0) {
        perror("bpf_obj_get");
        return 1;
    }

    // Loop through the map entries and display the key-value pairs
    printf("Map contents:\n");

    // Print the header
    printf("%-5s %-20s %-8s %-20s %-8s\n", "Key", "Source IP", "Port", "Destination IP", "Port");
    printf("------------------------------------------------------------\n");

    // Print the values for keys 0 to 9
    for (key = 0; key < 10; key++) {
        // Lookup the value for the current key
        if (bpf_map_lookup_elem(map_fd, &key, &value) < 0) {
            // Error handling for map lookup failure
            perror("bpf_map_lookup_elem");
            continue;
        }

        // Convert IP addresses to string format
        char src_ip_str[INET_ADDRSTRLEN];
        char dst_ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(value.src_ip), src_ip_str, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(value.dst_ip), dst_ip_str, INET_ADDRSTRLEN);

        // Print key-value pair
        printf("%-5u %-20s %-8u %-20s %-8u\n",
               key, src_ip_str, ntohs(value.src_port), dst_ip_str, ntohs(value.dst_port));
    }

    return 0;
}
