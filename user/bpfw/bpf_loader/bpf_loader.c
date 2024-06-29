#include "bpf_loader.h"

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include <linux/ethtool.h>
#include <linux/if.h>
#include <linux/if_link.h>
#include <linux/sockios.h>

#include <net/if.h>
#include <sys/ioctl.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "../common_user.h"
#include "../netlink/netlink.h"


// Struct to keep BPF object and program pointers together
struct bpf_handle {
    struct bpf_object  *obj;    // BPF object pointer
    struct bpf_program *prog;   // BPF program pointer

    bool  dsa;
    __u32 dsa_switch;

    /*struct {
        __u32 handle;
        __u32 priority;
    } tc;*/
};


static int check_dsa(struct bpf_handle *bpf, struct netlink_handle *netlink_h) {
    bpf->dsa_switch = 0;

    int rc = netlink_get_dsa_switch(netlink_h, &bpf->dsa_switch);
    if (rc < 0)
        return rc;

    if (!bpf->dsa)
        return 0;

    if (!bpf->dsa_switch) {
        //FW_ERROR("Error retrieving DSA interfaces: %s (-%d).\n", strerror(rc), rc);
        FW_ERROR("Error: Couldn't find a DSA interface.\n");
        return -1;
    }

    const char* rodata_dsa_sec = ".rodata.dsa";
    const char* bss_dsa_sec    = ".bss.dsa";

    // Find the .rodata section
    struct bpf_map *rodata_dsa = bpf_object__find_map_by_name(bpf->obj, rodata_dsa_sec);
    if (!rodata_dsa) {
        FW_ERROR("Error: BPF program wasn't built with DSA support (Couldn't find BPF section %s).\n",
            rodata_dsa_sec);

        return -1;
    }

    size_t rodata_dsa_size;
    struct dsa_info *dsa_info = bpf_map__initial_value(rodata_dsa, &rodata_dsa_size);
    if (!dsa_info) {
        FW_ERROR("Error: Failed to get DSA information from BPF %s.\n", rodata_dsa_sec);
        return -1;
    }

    // Find the .bss section
    struct bpf_map *bss_dsa = bpf_object__find_map_by_name(bpf->obj, bss_dsa_sec);
    if (!bss_dsa) {
        FW_ERROR("Error: Couldn't find BPF section %s.\n", bss_dsa_sec);
        return -1;
    }

    size_t bss_dsa_size;
    __u32 *dsa_switch = bpf_map__initial_value(bss_dsa, &bss_dsa_size);
    if (!dsa_info) {
        FW_ERROR("Error: Couldn't set DSA switch in BPF section %s.\n", bss_dsa_sec);
        return -1;
    }

    *dsa_switch = bpf->dsa_switch;

    return 0;
}

struct bpf_handle* bpf_load_program(const char *obj_path, enum bpf_prog_type prog_type, struct netlink_handle *netlink_h, bool dsa) {
    struct bpf_handle* bpf = (struct bpf_handle*)malloc(sizeof(struct bpf_handle));
    if (!bpf) {
        FW_ERROR("Error allocating BPF handle: %s (-%d).\n", strerror(errno), errno);
        return NULL;
    }

    // Try to open the BPF object file, return on error
    bpf->obj = bpf_object__open_file(obj_path, NULL);
    if (!bpf->obj) {
        FW_ERROR("Error opening BPF object file: %s (-%d).\n", strerror(errno), errno);
        goto free;
    }

    bpf->prog = bpf_object__next_program(bpf->obj, NULL);
    if (!bpf->prog) {
        FW_ERROR("Couldn't find a BPF program in %s.\n", obj_path);
        goto bpf_object__close;
    }
    
    bpf_program__set_type(bpf->prog, prog_type);

    bpf->dsa = dsa;
    if (check_dsa(bpf, netlink_h) != 0)
        goto bpf_object__close;

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

void bpf_unload_program(struct bpf_handle* bpf) {
    // Unpin the maps from /sys/fs/bpf
    bpf_object__unpin_maps(bpf->obj, NULL);
    bpf_object__close(bpf->obj);

    free(bpf);
}

int bpf_if_attach_program(struct bpf_handle* bpf, char* ifname, __u32 xdp_flags) {
    // Get the interface index from the interface name
    __u32 ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        FW_ERROR("Error finding network interface %s: %s (-%d).\n", ifname, strerror(errno), errno);
        return errno;
    }

    if (ifindex == bpf->dsa_switch && !bpf->dsa)
        return 0;
    
    enum bpf_prog_type prog_type = bpf_program__type(bpf->prog);
    switch (prog_type) {
        case BPF_PROG_TYPE_XDP:
            // Attach the program to the XDP hook
            if (bpf_xdp_attach(ifindex, bpf_program__fd(bpf->prog), xdp_flags, NULL) != 0) {
                FW_ERROR("Error attaching XDP program to %s: %s (-%d).\n", ifname, strerror(errno), errno);
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
                FW_ERROR("Error attaching TC program to %s: %s (-%d).\n", ifname, strerror(errno), errno);
                hook.attach_point |= BPF_TC_EGRESS;
                bpf_tc_hook_destroy(&hook);

                return errno;
            }

            /*bpf->tc.handle   = opts.handle;
            bpf->tc.priority = opts.priority;*/
        break;

        // If the program is not of type XDP or TC
        default:
            FW_ERROR("Error: BPF program type %d is not supported.\n", prog_type);
            return -1;
    }

    return 0;
}

void bpf_if_detach_program(struct bpf_handle* bpf, char* ifname, __u32 xdp_flags) {
    // Get the interface index from the interface name
    __u32 ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        FW_ERROR("Error finding network interface %s: %s (-%d).\n", ifname, strerror(errno), errno);
        return;
    }

    if (ifindex == bpf->dsa_switch && !bpf->dsa)
        return;

    enum bpf_prog_type prog_type = bpf_program__type(bpf->prog);
    switch (prog_type) {
        case BPF_PROG_TYPE_XDP:
            // Detach the program from the XDP hook
            bpf_xdp_detach(ifindex, xdp_flags, NULL);
        break;

        case BPF_PROG_TYPE_SCHED_CLS:
            DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex, .attach_point = BPF_TC_INGRESS);
            //DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts, .handle = bpf->tc.handle, .priority = bpf->tc.priority);

            // Detach the TC prgram
            //bpf_tc_detach(&hook, &opts);

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

int bpf_ifs_attach_program(struct bpf_handle* bpf, char* ifnames[], unsigned int ifname_size, __u32 xdp_flags) {
    // Iterate to all the given interfaces and attache the program to them
    for (int i = 0; i < ifname_size; i++) {
        int rc = bpf_if_attach_program(bpf, ifnames[i], xdp_flags);
        if (rc != 0) {
            // If an error occured while attaching to one interface, detach all the already attached programs
            while (--i >= 0)
                bpf_if_detach_program(bpf, ifnames[i], xdp_flags);

            return rc;
        }
    }

    return 0;
}

void bpf_ifs_detach_program(struct bpf_handle* bpf, char* ifnames[], unsigned int ifname_size, __u32 xdp_flags) {
    // Iterate to all the given interfaces and detache the program from them
    for (int i = 0; i < ifname_size; i++)
        bpf_if_detach_program(bpf, ifnames[i], xdp_flags);
}

int bpf_attach_program(struct bpf_handle* bpf, __u32 xdp_flags, struct netlink_handle *netlink_h) {
    // Retrieve the name and index of all network interfaces
    struct if_nameindex* ifaces = if_nameindex();
    if (!ifaces) {
        fprintf(stderr, "Error retrieving network interfaces: %s (-%d).\n", strerror(errno), errno);
        return errno;
    }

    int rc = 0;
    for (struct if_nameindex* iface = ifaces; iface->if_index && iface->if_name; iface++) {
        rc = netlink_if_should_attach(netlink_h, iface->if_index, bpf->dsa);
        if (rc < 0)
            goto error;

        if (rc == 0)
            continue;

        rc = bpf_if_attach_program(bpf, iface->if_name, xdp_flags);
        if (rc != 0) {
error:
            // If an error occured while attaching to one interface, detach all the already attached programs
            while (--iface >= ifaces)
                if (netlink_if_should_attach(netlink_h, iface->if_index, bpf->dsa) == 1)
                    bpf_if_detach_program(bpf, iface->if_name, xdp_flags);

            break;
        }
    }

    // Retrieved interfaces are dynamically allocated, so they must be freed
    if_freenameindex(ifaces);

    return rc;
}

int bpf_detach_program(struct bpf_handle* bpf, __u32 xdp_flags, struct netlink_handle *netlink_h) {
    // Retrieve the name and index of all network interfaces
    struct if_nameindex* ifaces = if_nameindex();
    if (!ifaces) {
        fprintf(stderr, "Error retrieving network interfaces: %s (-%d).\n", strerror(errno), errno);
        return errno;
    }

    for (struct if_nameindex* iface = ifaces; iface->if_index && iface->if_name; iface++)
        if (netlink_if_should_attach(netlink_h, iface->if_index, bpf->dsa) == 1)
            bpf_if_detach_program(bpf, iface->if_name, xdp_flags);

    // Retrieved interfaces are dynamically allocated, so they must be freed
    if_freenameindex(ifaces);

    return 0;
}

int bpf_get_map_fd(struct bpf_handle* bpf, const char *map_name) {
    return bpf_object__find_map_fd_by_name(bpf->obj, map_name);
}
