// loader.c
#include <stdio.h>
#include <stdlib.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include <errno.h>
#include <net/if.h>
#include <unistd.h> // Add this include for sleep function

#define IFNAME "wlp0s20f3"
#define PATH "/sys/fs/bpf/"

// Declaration for the display_map function
void display_map(struct bpf_object *obj);

int main() {
    struct bpf_object *obj_program1, *obj_program2;
    int ifIndex, progFd_program1, progFd_program2;
    char program1FileName[] = "xdp_program1.o";
    char program2FileName[] = "xdp_program2.o";
    int err;

    // Load the first XDP program
    err = bpf_prog_load(program1FileName, BPF_PROG_TYPE_XDP, &obj_program1, &progFd_program1, NULL);
    if (err) {
        fprintf(stderr, "Error: could not load first XDP program: %s\n", strerror(-err));
        return 1;
    }

    // Load the second XDP program
    err = bpf_prog_load(program2FileName, BPF_PROG_TYPE_XDP, &obj_program2, &progFd_program2, NULL);
    if (err) {
        fprintf(stderr, "Error: could not load second XDP program: %s\n", strerror(-err));
        return 1;
    }

    ifIndex = if_nametoindex(IFNAME);
    if (!ifIndex) {
        perror("if_nametoindex");
        return 1;
    }

    // Attach the first XDP program to the interface
    err = bpf_set_link_xdp_fd(ifIndex, progFd_program1, 0);
    if (err) {
        fprintf(stderr, "Error: Could not attach first XDP program to interface(%s): %s\n", IFNAME, strerror(-err));
        return 1;
    }

    // Attach the second XDP program to the interface
    err = bpf_set_link_xdp_fd(ifIndex, progFd_program2, 0);
    if (err) {
        fprintf(stderr, "Error: Could not attach second XDP program to interface(%s): %s\n", IFNAME, strerror(-err));
        return 1;
    }

    printf("Successfully linked XDP programs to interface(%s)\n", IFNAME);

    printf("\nPress \"Enter\" to unlink XDP programs\n");
    getchar();

    // Detach the first XDP program from the interface
    err = bpf_set_link_xdp_fd(ifIndex, -1, 0);
    if (err) {
        fprintf(stderr, "Error unlinking first XDP program from interface(%s): %s\n", IFNAME, strerror(-err));
        return 1;
    }

    // Detach the second XDP program from the interface
    err = bpf_set_link_xdp_fd(ifIndex, -1, 0);
    if (err) {
        fprintf(stderr, "Error unlinking second XDP program from interface(%s): %s\n", IFNAME, strerror(-err));
        return 1;
    }

    printf("Successfully unlinked XDP programs from interface(%s)\n", IFNAME);

    // Sleep for a while to give XDP programs a chance to execute
    sleep(1);

    // Display the contents of the map after detaching the XDP programs
    display_map(obj_program1);

    return 0;
}

// Implementation of the display_map function
void display_map(struct bpf_object *obj) {
    int map_fd, key, value;
    struct bpf_map *map;

    map = bpf_object__find_map_by_name(obj, "my_shared_map");
    if (!map) {
        fprintf(stderr, "Error: could not find the shared map in the object file\n");
        return;
    }

    map_fd = bpf_map__fd(map);

    printf("Map contents:\n");

    // Loop through the map entries and display the key-value pairs
    key = -1;
    while (bpf_map_get_next_key(map_fd, &key, &key) == 0) {
        // Lookup the value for the current key
        if (bpf_map_lookup_elem(map_fd, &key, &value) < 0) {
            // The element does not exist in the map (unlikely)
            printf("Key %d: Not present\n", key);
        } else {
            // The element exists in the map
            printf("Key %d: Value %d\n", key, value);
        }
    }
}
