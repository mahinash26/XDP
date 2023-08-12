#include <stdio.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define MAP_PATH "/sys/fs/bpf/my_map"

int main()
{
    int map_fd, value;
    int key;
    int value1; // Use int data type here

    map_fd = bpf_obj_get(MAP_PATH);
    if (map_fd < 0)
    {
        perror("bpf_obj_get");
        return 1;
    }

    // Loop through the map entries and display the key-value pairs
    printf("Map contents:\n");

    // Get the first key in the map
    key = 0;
    int next_key;
    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0)
    {
        // Lookup the value for the current key
        if (bpf_map_lookup_elem(map_fd, &key, &value) < 0)
        {
            // The element does not exist in the map (unlikely)
            printf("Key %d: Not present\n", key);
        }
        else
        {
            // The element exists in the map
            printf("Key %d: Value %d\n", key, value);
        }

        // Move to the next key
        key = next_key;
    }

    printf("Enter the key to update or add: ");
    scanf("%d", &key);

    if (bpf_map_lookup_elem(map_fd, &key, &value) < 0)
    {
        // The element does not exist in the map
        printf("The key %d does not exist in the map.\n", key);
    }
    else
    {
        // The element exists in the map
        printf("The key %d already exists in the map with value: %d.\n", key, value);

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

    // Reset key to -1 to start iterating from the beginning
    key = 0;
    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0)
    {
        // Lookup the value for the current key
        if (bpf_map_lookup_elem(map_fd, &key, &value) < 0)
        {
            // The element does not exist in the map (unlikely)
            printf("Key %d: Not present\n", key);
        }
        else
        {
            // The element exists in the map
            printf("Key %d: Value %d\n", key, value);
        }

        // Move to the next key
        key = next_key;
    }

    return 0;
}

