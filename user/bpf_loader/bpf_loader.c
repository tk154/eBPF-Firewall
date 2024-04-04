#include "bpf_loader.h"

#include <errno.h>
#include <stdlib.h>

#include <linux/if_link.h>
#include <net/if.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "../common_user.h"


// For now, attach XDP programs in SKB/Generic mode
#define XDP_ATTACH_FLAGS XDP_FLAGS_SKB_MODE

// Struct to keep BPF object and program pointers together
struct bpf_object_program {
    struct bpf_object*  obj;    // BPF object pointer
    struct bpf_program* prog;   // BPF program pointer
};


struct bpf_object_program* bpf_load_program(const char* prog_path, enum bpf_prog_type prog_type) {
    struct bpf_object_program* bpf = (struct bpf_object_program*)malloc(sizeof(struct bpf_object_program));
    if (!bpf) {
        FW_ERROR("Error allocating BPF handle: %s (-%d).\n", strerror(errno), errno);
        return NULL;
    }

    // Try to open the BPF object file, return on error
    bpf->obj = bpf_object__open_file(prog_path, NULL);
    if (!bpf->obj) {
        FW_ERROR("Error opening BPF object file: %s (-%d).\n", strerror(errno), errno);
        goto free;
    }

    bpf->prog = bpf_object__next_program(bpf->obj, NULL);
    if (!bpf->prog) {
        FW_ERROR("Couldn't find a BPF program in %s.\n", prog_path);
        goto bpf_object__close;
    }
    
    bpf_program__set_type(bpf->prog, prog_type);

    // Try to load the BPF object into the kernel, return on error
    if (bpf_object__load(bpf->obj) != 0) {
        FW_ERROR("Error loading BPF program into kernel: %s (-%d).\n", strerror(errno), errno);
        goto bpf_object__close;
    }

    return bpf;

bpf_object__close:
    bpf_object__close(bpf->obj);

free:
    free(bpf);

    return NULL;
}

void bpf_unload_program(struct bpf_object_program* bpf) {
    // Unpin the maps from /sys/fs/bpf
    bpf_object__unpin_maps(bpf->obj, NULL);
    bpf_object__close(bpf->obj);

    free(bpf);
}

int bpf_if_attach_program(struct bpf_object_program* bpf, char* ifname) {
    // Get the interface index from the interface name
    unsigned int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        FW_ERROR("Error finding network interface %s: %s (-%d).\n", ifname, strerror(errno), errno);
        return errno;
    }
    
    enum bpf_prog_type prog_type = bpf_program__type(bpf->prog);
    switch (prog_type) {
        case BPF_PROG_TYPE_XDP:
            // Attach the program to the XDP hook
            if (bpf_xdp_attach(ifindex, bpf_program__fd(bpf->prog), XDP_ATTACH_FLAGS, NULL) != 0) {
                FW_ERROR("Error attaching XDP program: %s (-%d).\n", strerror(errno), errno);
                return errno;
            }
        break;

        case BPF_PROG_TYPE_SCHED_CLS:
            DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex, .attach_point = BPF_TC_INGRESS);
            DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts, .prog_fd = bpf_program__fd(bpf->prog));

            // Create a TC hook on the ingress of the interface
            // bpf_tc_hook_create will return an error and print an error message if the hook already exists
            int rc = bpf_tc_hook_create(&hook);
            if (rc == -EEXIST)
                FW_ERROR("TC hook already exists on %s. You can ignore the kernel error message.\n\n", ifname);
            else if (rc != 0) {
                FW_ERROR("Error creating TC hook: %s (-%d).\n", strerror(errno), errno);
                return errno;
            }

            // Attach the TC prgram to the created hook
            if (bpf_tc_attach(&hook, &opts) != 0) {
                FW_ERROR("Error attaching TC program on %s: %s (-%d).\n", ifname, strerror(errno), errno);
                hook.attach_point |= BPF_TC_EGRESS;
                bpf_tc_hook_destroy(&hook);

                return errno;
            }
        break;

        // If the program is not of type XDP or TC
        default:
            FW_ERROR("Error: BPF program type %d is not supported.\n", prog_type);
            return -1;
    }

    return 0;
}

void bpf_if_detach_program(struct bpf_object_program* bpf, char* ifname) {
    // Get the interface index from the interface name
    unsigned int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        FW_ERROR("Error finding network interface %s: %s (-%d).\n", ifname, strerror(errno), errno);
        return;
    }

    enum bpf_prog_type prog_type = bpf_program__type(bpf->prog);
    switch (prog_type) {
        case BPF_PROG_TYPE_XDP:
            // Detach the program from the XDP hook
            bpf_xdp_detach(ifindex, XDP_ATTACH_FLAGS, NULL);
        break;

        case BPF_PROG_TYPE_SCHED_CLS:
            DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex, .attach_point = BPF_TC_INGRESS);
            DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts, .prog_fd = bpf_program__fd(bpf->prog));

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

        // If the program is not of type XDP or TC
        default:
            FW_ERROR("Error: BPF program type %d is not supported.\n", prog_type);
    }
}

int bpf_ifs_attach_program(struct bpf_object_program* bpf, char* ifnames[], unsigned int ifname_size) {
    // Iterate to all the given interfaces and attache the program to them
    for (int i = 0; i < ifname_size; i++) {
        int rc = bpf_if_attach_program(bpf, ifnames[i]);
        if (rc != 0) {
            // If an error occured while attaching to one interface, detach all the already attached programs
            while (--i >= 0)
                bpf_if_detach_program(bpf, ifnames[i]);

            return rc;
        }
    }

    return 0;
}

void bpf_ifs_detach_program(struct bpf_object_program* bpf, char* ifnames[], unsigned int ifname_size) {
    // Iterate to all the given interfaces and detache the program from them
    for (int i = 0; i < ifname_size; i++)
        bpf_if_detach_program(bpf, ifnames[i]);
}

int bpf_get_map_fd(struct bpf_object_program* bpf, const char *map_name) {
    return bpf_object__find_map_fd_by_name(bpf->obj, map_name);
}
