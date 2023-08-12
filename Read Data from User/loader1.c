#include <stdio.h>
#include <stdlib.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include <errno.h>
#include <net/if.h>

#define IFNAME "wlp0s20f3"
#define PATH "/sys/fs/bpf/"

int main()
{
    struct bpf_object *obj;
    struct bpf_program *prog;
    int ifIndex, progFd;
    char fileName[] = "xdp_program.o";
    int err;

    // Load the BPF object from the specified file
    err = bpf_prog_load(fileName, BPF_PROG_TYPE_XDP, &obj, &progFd);
    if (err)
    {
        fprintf(stderr, "Error: could not load bpf program: %s\n", strerror(-err));
        return 1;
    }

    // Find the XDP program within the BPF object
    prog = bpf_object__find_program_by_type(obj, BPF_PROG_TYPE_XDP);
    if (!prog)
    {
        fprintf(stderr, "Error: could not find XDP program in the object\n");
        return 1;
    }

    // Get the interface index for the specified network interface name
    ifIndex = if_nametoindex(IFNAME);
    if (!ifIndex)
    {
        perror("if_nametoindex");
        return 1;
    }

    // Attach the loaded XDP program to the network interface using XDP
    err = bpf_set_link_xdp_fd(ifIndex, progFd, 0);
    if (err)
    {
        fprintf(stderr, "Error: Could not link XDP program to interface(%s): %s\n", IFNAME, strerror(-err));
        return 1;
    }

    // Pin the BPF maps to /sys/fs/bpf/
    if (bpf_object__pin_maps(obj, PATH) < 0)
    {
        fprintf(stderr, "Error: Could not pin map to (%s): %s\n", PATH, strerror(errno));
        return 1;
    }
    printf("Successfully linked XDP program to interface(%s)\n", IFNAME);

    printf("\nPress \"Enter\" to unlink XDP program\n");
    getchar();

    // Unlink the BPF program from the network interface
    err = bpf_set_link_xdp_fd(ifIndex, -1, 0);
    if (err)
    {
        fprintf(stderr, "Error unlinking XDP program from interface(%s): %s\n", IFNAME, strerror(-err));
        return 1;
    }

    // Unpin the BPF maps from /sys/fs/bpf/
    if (bpf_object__unpin_maps(obj, PATH) < 0)
    {
        fprintf(stderr, "Error: Could not unpin map from (%s): %s\n", PATH, strerror(errno));
        return 1;
    }
    printf("Successfully unlinked XDP program from interface(%s)\n", IFNAME);

    // Free the BPF object
    bpf_object__close(obj);

    return 0;
}

