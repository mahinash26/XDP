#include <stdio.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define MAP_PATH "/sys/fs/bpf/outer_map"

int main()
{
    int map_fd, value;
    __u32 key; // Change key to __u32
    int value1;

    map_fd = bpf_obj_get(MAP_PATH);
    if (map_fd < 0)
    {
        perror("bpf_obj_get");
        return 1;
    }

    // Loop through the map entries and display the key-value pairs
    printf("Map contents:\n");

    // Print the values for keys 0 to 9
    for (key = 0; key < 2; key++)
    {
        // Lookup the value for the current key
        if (bpf_map_lookup_elem(map_fd, &key, &value) < 0)
        {
            // The element does not exist in the map
            printf("Key %u: Not present\n", key);
        }
        else
        {
            // The element exists in the map
            printf("Key %u: Value %d\n", key, value);
        }
    }

    printf("Enter the key to update or add: ");
    scanf("%u", &key); // Use %u format specifier for __u32 key

    if (bpf_map_lookup_elem(map_fd, &key, &value) < 0)
    {
        // The element does not exist in the map
        printf("The key %u does not exist in the map.\n", key);
    }
    else
    {
        // The element exists in the map
        printf("The key %u already exists in the map with value: %d.\n", key, value);

        // Read the new value from the user
        printf("Enter the new value: ");
        scanf("%d", &value1);

        // Update the value in the map
        if (bpf_map_update_elem(map_fd, &key, &value1, BPF_ANY))
        {
            perror("bpf_map_update_elem");
            return 1;
        }

        printf("Key-Value pair updated in the map.\n");
    }

    // Print the entire map again after the update
    printf("Updated map contents:\n");

    // Print the values for keys 0 to 9 after the update
    for (key = 0; key < 10; key++)
    {
        // Lookup the value for the current key
        if (bpf_map_lookup_elem(map_fd, &key, &value) < 0)
        {
            // The element does not exist in the map
            printf("Key %u: Not present\n", key);
        }
        else
        {
            // The element exists in the map
            printf("Key %u: Value %d\n", key, value);
        }
    }

    return 0;
}