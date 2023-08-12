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
    struct bpf_map_info map_info;
    int map_fd, next_key;
    struct ip_data key_data;
    __u64 value;
    
    // Open the BPF map
    map_fd = bpf_obj_get(MAP_PATH);
    if (map_fd < 0) {
        perror("bpf_obj_get");
        return 1;
    }

    // Get map information
    __u32 info_len = sizeof(map_info);
    if (bpf_obj_get_info_by_fd(map_fd, &map_info, &info_len) < 0) {
        perror("bpf_obj_get_info_by_fd");
        return 1;
    }
    __u32 map_size = map_info.max_entries;

    // Set max_iterations to the number of entries in the map
    int max_iterations = 1;
    
    // Loop through the map entries and display the key-value pairs
    printf("Map contents:\n");

    // Print the header
    printf("%-5s %-20s %-8s %-20s %-8s %-8s\n", "Key", "Source IP", "Port", "Destination IP", "Port", "Counter");
    printf("----------------------------------------------------------------------\n");

    next_key = 0;
    int iterations = 0; // Initialize the iteration counter
    while (bpf_map_get_next_key(map_fd, &next_key, &key_data) == 0 && iterations < max_iterations) {
        // Lookup the value for the current key
        if (bpf_map_lookup_elem(map_fd, &key_data, &value) < 0) {
            // Error handling for map lookup failure
            perror("bpf_map_lookup_elem");
            continue;
        }

        // Convert IP addresses to string format
        char src_ip_str[INET_ADDRSTRLEN];
        char dst_ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(key_data.src_ip), src_ip_str, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(key_data.dst_ip), dst_ip_str, INET_ADDRSTRLEN);

        // Print key-value pair and counter
        printf("%-5u %-20s %-8u %-20s %-8u %-8llu\n",
            next_key, src_ip_str, ntohs(key_data.src_port), dst_ip_str, ntohs(key_data.dst_port), (unsigned long long)value);


        next_key++;
        iterations++; // Increment the iteration counter
    }

    return 0;
}


/*
bpf_obj_get(MAP_PATH):

MAP_PATH: A macro representing the path to the BPF map file.
This function opens and returns a file descriptor (map_fd) for the specified BPF map file.
bpf_obj_get_info_by_fd(map_fd, &map_info, &info_len):

map_fd: The file descriptor obtained from bpf_obj_get.
&map_info: A pointer to a struct bpf_map_info where information about the map will be stored.
&info_len: A pointer to an __u32 variable that holds the length of the map info structure.
This function retrieves information about the BPF map associated with the given file descriptor.
bpf_map_get_next_key(map_fd, &next_key, &key_data):

map_fd: The file descriptor of the BPF map.
&next_key: A pointer to an integer that holds the current key, and will be updated to the next key in the loop.
&key_data: A pointer to a struct ip_data where the next key data will be stored.
This function retrieves the next key and its associated data in the BPF map.
bpf_map_lookup_elem(map_fd, &key_data, &value):

map_fd: The file descriptor of the BPF map.
&key_data: A pointer to a struct ip_data containing the key for which you want to look up the value.
&value: A pointer to a variable where the value associated with the given key will be stored.
This function looks up the value associated with a specific key in the BPF map.
inet_ntop(AF_INET, &(key_data.src_ip), src_ip_str, INET_ADDRSTRLEN):

AF_INET: Address family, in this case, IPv4.
&(key_data.src_ip): A pointer to the source IP address in the ip_data structure.
src_ip_str: A character array where the converted source IP address will be stored as a string.
INET_ADDRSTRLEN: A constant indicating the maximum length of an IPv4 address string.
This function converts an IPv4 address from binary to string format.
inet_ntop(AF_INET, &(key_data.dst_ip), dst_ip_str, INET_ADDRSTRLEN):

Similar to the previous function call, but for the destination IP address.
printf("%-5u %-20s %-8u %-20s %-8u %-8llu\n", ...)

This is a formatted print statement that displays the key, source IP, source port, destination IP, destination port, and counter.
*/