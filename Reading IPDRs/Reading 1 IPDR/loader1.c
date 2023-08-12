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
            err = bpf_prog_load(fileName, BPF_PROG_TYPE_XDP, &obj, &progFd);
            if (err)
            {
                fprintf(stderr, "Error: could not load bpf program: %s\n", strerror(-err));
                return 1;
            }

            ifIndex = if_nametoindex(IFNAME);
            if (!ifIndex)
            {
                perror("if_nametoindex");
                return 1;
            }

            err = bpf_set_link_xdp_fd(ifIndex, progFd, 0);
            if (err)
            {
                fprintf(stderr, "Error: Could not link XDP program to interface(%s): %s\n", IFNAME, strerror(-err));
                return 1;
            }

            if (bpf_object__pin_maps(obj, PATH) < 0)
            {
                fprintf(stderr, "Error: Could not pin map to (%s): %s\n", PATH, strerror(errno));
                return 1;
            }
            printf("Successfully linked XDP program to interface(%s)\n", IFNAME);
        }
        else if (strcmp(command, "unload") == 0)
        {
            err = bpf_set_link_xdp_fd(ifIndex, -1, 0);
            if (err)
            {
                fprintf(stderr, "Error unlinking XDP program from interface(%s): %s\n", IFNAME, strerror(-err));
                return 1;
            }
            if (bpf_object__unpin_maps(obj, PATH) < 0)
            {
                fprintf(stderr, "Error: Could not unpin map from (%s): %s\n", PATH, strerror(errno));
                return 1;
            }
            printf("Successfully unlinked XDP program from interface(%s)\n", IFNAME);
        }
        else if (strcmp(command, "exit") == 0)
        {
            break;
        }
        else
        {
            printf("Invalid command. Please enter 'load', 'unload', or 'exit'.\n");
        }
    }

    return 0;
}

