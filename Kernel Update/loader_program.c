#include <stdio.h>
#include <stdlib.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include <errno.h>
#include <net/if.h>

#define IFNAME "wlxb4b024d34376"
#define PATH "/sys/fs/bpf/"

int main()
{
    struct bpf_object *obj;
    int ifIndex, progFd;
    char fileName[] = "xdp_program.o";
    int err;

    while (1)
    {
        printf("Enter 'load' to load XDP program or 'unload' to unload XDP program. Type 'exit' to quit.\n");
        char command[100];
        if (fgets(command, sizeof(command), stdin) == NULL)
        {
            fprintf(stderr, "Error reading command.\n");
            return 1;
        }

        command[strcspn(command, "\n")] = '\0'; // Remove the trailing newline character

        if (strcmp(command, "load") == 0)
        {
            // Load the XDP program
            err = bpf_prog_load(fileName, BPF_PROG_TYPE_XDP, &obj, &progFd);
            if (err)
            {
                fprintf(stderr, "Error: could not load bpf program: %s\n", strerror(-err));
                return 1;
            }

            // Get the network interface index using its name
            ifIndex = if_nametoindex(IFNAME);
            if (!ifIndex)
            {
                perror("if_nametoindex");
                return 1;
            }

            // Link the XDP program to the network interface
            err = bpf_set_link_xdp_fd(ifIndex, progFd, 0);
            if (err)
            {
                fprintf(stderr, "Error: Could not link XDP program to interface(%s): %s\n", IFNAME, strerror(-err));
                return 1;
            }

            // Pin the BPF maps to a specified path for persistence
            if (bpf_object__pin_maps(obj, PATH) < 0)
            {
                fprintf(stderr, "Error: Could not pin map to (%s): %s\n", PATH, strerror(errno));
                return 1;
            }
            printf("Successfully linked XDP program to interface(%s)\n", IFNAME);
        }
        else if (strcmp(command, "unload") == 0)
        {
            // Unlink the XDP program from the network interface
            err = bpf_set_link_xdp_fd(ifIndex, -1, 0);
            if (err)
            {
                fprintf(stderr, "Error unlinking XDP program from interface(%s): %s\n", IFNAME, strerror(-err));
                return 1;
            }
            
            // Unpin the BPF maps from the specified path
            if (bpf_object__unpin_maps(obj, PATH) < 0)
            {
                fprintf(stderr, "Error: Could not unpin map from (%s): %s\n", PATH, strerror(errno));
                return 1;
            }
            printf("Successfully unlinked XDP program from interface(%s)\n", IFNAME);
        }
        else if (strcmp(command, "exit") == 0)
        {
            break; // Exit the loop and the program
        }
        else
        {
            printf("Invalid command. Please enter 'load', 'unload', or 'exit'.\n");
        }
    }

    return 0;
}


/*
Explanation and Comments:

This program provides a user interface to load and unload an XDP program to/from a specific network interface and pin/unpin associated BPF maps to/from a specified path.

The bpf_prog_load function loads an XDP program from a file and returns a file descriptor (progFd) for the loaded program. The bpf_object__pin_maps function is used to pin the BPF maps for persistence.

The if_nametoindex function retrieves the network interface index based on its name.

The bpf_set_link_xdp_fd function links an XDP program to a network interface using its index (ifIndex). A program can be unlinked by passing -1 as the second argument.

The bpf_object__unpin_maps function is used to unpin BPF maps, allowing them to be removed from the specified path.

The program uses a loop to continuously prompt the user for commands. Entering "load" loads the XDP program, "unload" unloads it, and "exit" exits the program.

The program handles errors and provides appropriate error messages for different scenarios.

This code provides an interactive way to manage the loading and unloading of XDP programs on a specific network interface and pin/unpin BPF maps for persistence.
*/
