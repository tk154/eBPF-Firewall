#include "bpf_loader.h"

#include <errno.h>
#include <glob.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <net/if.h>
#include <linux/if_link.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

// For now, attach XDP programs in SKB/Generic mode
#define XDP_ATTACH_FLAGS XDP_FLAGS_SKB_MODE


// BPF object pointer
static struct bpf_object *bpf_obj;

// BPF program pointer
static struct bpf_program *bpf_prog;


int bpf_load_program(const char* prog_path, enum bpf_prog_type prog_type) {
    // Try to open the BPF object file, return on error
    bpf_obj = bpf_object__open_file(prog_path, NULL);
    if (!bpf_obj) {
        fprintf(stderr, "Error opening BPF object file: %s (-%d).\n", strerror(errno), errno);
        return errno;
    }

    bpf_prog = bpf_object__next_program(bpf_obj, NULL);
    if (!bpf_prog) {
        fprintf(stderr, "Couldn't find a BPF program in %s.\n", prog_path);
        bpf_object__close(bpf_obj);

        return ENOENT;
    }
    
    bpf_program__set_type(bpf_prog, prog_type);

    // Try to load the BPF object into the kernel, return on error
    if (bpf_object__load(bpf_obj) != 0) {
        fprintf(stderr, "Error loading BPF program into kernel: %s (-%d).\n", strerror(errno), errno);
        bpf_object__close(bpf_obj);

        return errno;
    }

    return 0;
}

void bpf_unload_program() {
    // Unpin the maps from /sys/fs/bpf
    bpf_object__unpin_maps(bpf_obj, NULL);
    bpf_object__close(bpf_obj);
}

int bpf_if_attach_program(char* ifname) {
    // Get the interface index from the interface name
    unsigned int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        fprintf(stderr, "Error finding network interface %s: %s (-%d).\n", ifname, strerror(errno), errno);
        return errno;
    }
    
    enum bpf_prog_type prog_type = bpf_program__type(bpf_prog);
    switch (prog_type) {
        case BPF_PROG_TYPE_XDP:
            // Attach the program to the XDP hook
            if (bpf_xdp_attach(ifindex, bpf_program__fd(bpf_prog), XDP_ATTACH_FLAGS, NULL) != 0) {
                fprintf(stderr, "Error attaching XDP program: %s (-%d).\n", strerror(errno), errno);
                return errno;
            }
        break;

        case BPF_PROG_TYPE_SCHED_CLS:
            DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex, .attach_point = BPF_TC_INGRESS);
            DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts, .prog_fd = bpf_program__fd(bpf_prog));

            // Create a TC hook on the ingress of the interface
            // bpf_tc_hook_create will return an error and print an error message if the hook already exists
            int rc = bpf_tc_hook_create(&hook);
            if (rc == -EEXIST)
                fprintf(stderr, "TC hook already exists on %s. You can ignore the kernel error message.\n\n", ifname);
            else if (rc != 0) {
                fprintf(stderr, "Error creating TC hook: %s (-%d).\n", strerror(errno), errno);
                return errno;
            }

            // Attach the TC prgram to the created hook
            if (bpf_tc_attach(&hook, &opts) != 0) {
                fprintf(stderr, "Error attaching TC program on %s: %s (-%d).\n", ifname, strerror(errno), errno);
                hook.attach_point |= BPF_TC_EGRESS;
                bpf_tc_hook_destroy(&hook);

                return errno;
            }
        break;
    }

    return 0;
}

void bpf_if_detach_program(char* ifname) {
    // Get the interface index from the interface name
    unsigned int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        fprintf(stderr, "Error finding network interface %s: %s (-%d).\n", ifname, strerror(errno), errno);
        return;
    }

    enum bpf_prog_type prog_type = bpf_program__type(bpf_prog);
    switch (prog_type) {
        case BPF_PROG_TYPE_XDP:
            // Detach the program from the XDP hook
            bpf_xdp_detach(ifindex, XDP_ATTACH_FLAGS, NULL);
        break;

        case BPF_PROG_TYPE_SCHED_CLS:
            DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex, .attach_point = BPF_TC_INGRESS);
            DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts, .prog_fd = bpf_program__fd(bpf_prog));

            /* It should be possible to detach the TC program from the hook, 
               check the hook if there is still another program attached to it
               and destroy the hook if not, but bpf_tc_detach always returns Invalid argument(-22)
               which means that TC programs cannot be detached, so for now just destroy the hook
               although there might be other programs attached to it */
            //printf("detach: %d\n", bpf_tc_detach(&hook, &opts));

            //if (bpf_tc_query(&hook, NULL) == -ENOENT) {
                // Needed to really destroy the qdisc hook and not just detaching the programs from it
                hook.attach_point |= BPF_TC_EGRESS;
                bpf_tc_hook_destroy(&hook);
            //}
        break;
    }
}

int bpf_ifs_attach_program(char* ifnames[], unsigned int ifname_size) {
    // Iterate to all the given interfaces and attache the program to them
    for (int i = 0; i < ifname_size; i++) {
        int rc = bpf_if_attach_program(ifnames[i]);
        if (rc != 0) {
            // If an error occured while attaching to one interface, detach all the already attached programs
            while (--i >= 0)
                bpf_if_detach_program(ifnames[i]);

            return rc;
        }
    }

    return 0;
}

void bpf_ifs_detach_program(char* ifnames[], unsigned int ifname_size) {
    // Iterate to all the given interfaces and detache the program from them
    for (int i = 0; i < ifname_size; i++)
        bpf_if_detach_program(ifnames[i]);
}

int bpf_get_map_fd(const char *map_name) {
    return bpf_object__find_map_fd_by_name(bpf_obj, map_name);
}
