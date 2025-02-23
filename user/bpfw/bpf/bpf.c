#include "bpf_loader.h"

#include <errno.h>
#include <stdlib.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <net/if.h>
#include <linux/if_link.h>

#include "../netlink/netlink.h"
#include "../logging/logging.h"


// Struct to keep BPF object and program pointers together
struct bpf_handle {
    struct bpf_object  *obj;    // BPF object pointer
    struct bpf_program *prog;   // BPF program pointer

    enum bpfw_hook hook;

    //struct {
    //    __u32 handle;
    //    __u32 priority;
    //} tc;
};


static __u32 get_xdp_flag(enum bpfw_hook hook) {
    switch (hook) {
        case BPFW_HOOK_XDP_GENERIC:
            return XDP_FLAGS_SKB_MODE;
        case BPFW_HOOK_XDP_NATIVE:
            return XDP_FLAGS_DRV_MODE;
        case BPFW_HOOK_XDP_OFFLOAD:
            return XDP_FLAGS_HW_MODE;
        default:
            return 0;
    }
}

static void *bpf_get_section_data(struct bpf_handle *bpf, const char *sec_name, size_t *sec_size) {
    // Find the .rodata section
    struct bpf_map *section = bpf_object__find_map_by_name(bpf->obj, sec_name);
    if (!section) {
        bpfw_error("Error: Couldn't find BPF section %s.\n", sec_name);
        return NULL;
    }

    size_t section_size;
    void *section_data = bpf_map__initial_value(section, &section_size);

    if (!section_data) {
        bpfw_error("Error: Failed to get data from BPF section %s.\n", sec_name);
        return NULL;
    }

    if (sec_size)
        *sec_size = section_size;

    return section_data;
}

static int bpf_ifname_attach_program(struct bpf_handle* bpf, char* ifname) {
    // Get the interface index from the interface name
    __u32 ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        bpfw_error("Error finding network interface %s: %s (-%d).\n", ifname, strerror(errno), errno);
        return BPFW_RC_ERROR;
    }

    return bpf_ifindex_attach_program(bpf, ifindex);
}

static int bpf_ifname_detach_program(struct bpf_handle* bpf, char* ifname) {
    // Get the interface index from the interface name
    __u32 ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        bpfw_error("Error finding network interface %s: %s (-%d).\n", ifname, strerror(errno), errno);
        return BPFW_RC_ERROR;
    }

    bpf_ifindex_detach_program(bpf, ifindex);

    return BPFW_RC_OK;
}


int bpf_ifindex_attach_program(struct bpf_handle* bpf, __u32 ifindex) {
    if (bpf->hook & BPFW_HOOK_XDP) {
        // Attach the program to the XDP hook
        if (bpf_xdp_attach(ifindex, bpf_program__fd(bpf->prog), get_xdp_flag(bpf->hook), NULL) != 0) {
            bpfw_error_ifindex("Error attaching XDP program to ", ifindex, "", errno);
            return BPFW_RC_ERROR;
        }
    }
    else {
        DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex, .attach_point = BPF_TC_INGRESS);
        DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts, .prog_fd = bpf_program__fd(bpf->prog));

        // Create a TC hook on the ingress of the interface
        // bpf_tc_hook_create will return an error and print an error message if the hook already exists
        int rc = bpf_tc_hook_create(&hook);
        if (rc == -EEXIST) {
            bpfw_error_ifindex("TC hook already exists on ", ifindex, "", 0);
            bpfw_error("You can ignore the kernel error message.\n\n");
        }
        else if (rc != 0) {
            bpfw_error("Error creating TC hook: %s (-%d).\n", strerror(errno), errno);
            return BPFW_RC_ERROR;
        }

        // Attach the TC prgram to the created hook
        if (bpf_tc_attach(&hook, &opts) != 0) {
            bpfw_error_ifindex("Error attaching TC program to ", ifindex, "", errno);

            hook.attach_point |= BPF_TC_EGRESS;
            bpf_tc_hook_destroy(&hook);

            return BPFW_RC_ERROR;
        }

        /*bpf->tc.handle   = opts.handle;
        bpf->tc.priority = opts.priority;*/
    }

    return BPFW_RC_OK;
}

void bpf_ifindex_detach_program(struct bpf_handle* bpf, __u32 ifindex) {
    if (bpf->hook & BPFW_HOOK_XDP) {
        // Detach the program from the XDP hook
        bpf_xdp_detach(ifindex, get_xdp_flag(bpf->hook), NULL);
    }
    else {
        DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex, .attach_point = BPF_TC_INGRESS);
        //DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts, .handle = bpf->tc.handle, .priority = bpf->tc.priority);

        // Detach the TC prgram
        //bpf_tc_detach(&hook, &opts);

        //if (bpf_tc_query(&hook, NULL) == -ENOENT) {
            // Needed to really destroy the qdisc hook and not just detaching the programs from it
            hook.attach_point |= BPF_TC_EGRESS;
            bpf_tc_hook_destroy(&hook);
        //}
    }
}


int bpf_ifnames_attach_program(struct bpf_handle* bpf, char* ifnames[], unsigned int ifname_size) {
    // Iterate to all the given interfaces and attache the program to them
    for (int i = 0; i < ifname_size; i++) {
        int rc = bpf_ifname_attach_program(bpf, ifnames[i]);
        if (rc != BPFW_RC_OK) {
            // If an error occured while attaching to one interface, detach all the already attached programs
            while (--i >= 0)
                bpf_ifname_detach_program(bpf, ifnames[i]);

            return rc;
        }
    }

    return BPFW_RC_OK;
}

void bpf_ifnames_detach_program(struct bpf_handle* bpf, char* ifnames[], unsigned int ifname_size) {
    // Iterate to all the given interfaces and detache the program from them
    for (int i = 0; i < ifname_size; i++)
        bpf_ifname_detach_program(bpf, ifnames[i]);
}

int bpf_attach_program(struct bpf_handle* bpf, struct netlink_handle *netlink_h) {
    // Retrieve the name and index of all network interfaces
    struct if_nameindex* ifaces = if_nameindex();
    if (!ifaces) {
        bpfw_error("Error retrieving network interfaces: %s (-%d).\n", strerror(errno), errno);
        return BPFW_RC_ERROR;
    }

    int rc = BPFW_RC_OK;
    for (struct if_nameindex* iface = ifaces; iface->if_index && iface->if_name; iface++) {
        rc = netlink_ifindex_should_attach(netlink_h, iface->if_index);
        switch (rc) {
            case BPFW_RC_ERROR:
                goto error;

            case NL_INTERFACE_DO_NOT_ATTACH:
                continue;
        }

        rc = bpf_ifindex_attach_program(bpf, iface->if_index);
        if (rc != BPFW_RC_OK) {
error:
            // If an error occured while attaching to one interface, detach all the already attached programs
            while (--iface >= ifaces)
                if (netlink_ifindex_should_attach(netlink_h, iface->if_index) == NL_INTERFACE_DO_ATTACH)
                    bpf_ifindex_detach_program(bpf, iface->if_index);

            break;
        }
    }

    // Retrieved interfaces are dynamically allocated, so they must be freed
    if_freenameindex(ifaces);

    return rc;
}

int bpf_detach_program(struct bpf_handle* bpf, struct netlink_handle *netlink_h) {
    // Retrieve the name and index of all network interfaces
    struct if_nameindex* ifaces = if_nameindex();
    if (!ifaces) {
        bpfw_error("Error retrieving network interfaces: %s (-%d).\n", strerror(errno), errno);
        return BPFW_RC_ERROR;
    }

    for (struct if_nameindex* iface = ifaces; iface->if_index && iface->if_name; iface++)
        if (netlink_ifindex_should_attach(netlink_h, iface->if_index) == NL_INTERFACE_DO_ATTACH)
            bpf_ifindex_detach_program(bpf, iface->if_index);

    // Retrieved interfaces are dynamically allocated, so they must be freed
    if_freenameindex(ifaces);

    return BPFW_RC_OK;
}


int bpf_get_map_fd(struct bpf_handle *bpf, const char *map_name) {
    // Get the file descriptor of the BPF flow map
    int map_fd = bpf_object__find_map_fd_by_name(bpf->obj, map_name);
    if (map_fd < 0) {
        bpfw_error("Error: Couldn't find BPF map %s.\n", map_name);
        return BPFW_RC_ERROR;
    }

    return map_fd;
}

int bpf_set_map_max_entries(struct bpf_handle *bpf, const char *map_name, __u32 new_max_entries) {
    struct bpf_map *map = bpf_object__find_map_by_name(bpf->obj, map_name);
    if (!map) {
        bpfw_error("Error: Couldn't find BPF map %s.\n", map_name);
        return BPFW_RC_ERROR;
    }

    if (bpf_map__set_max_entries(map, new_max_entries) != 0) {
        bpfw_error("Error setting %s max entries: %s (-%d).\n",
            map_name, strerror(errno), errno);

        return BPFW_RC_ERROR;
    }

    return BPFW_RC_OK;
}

int bpf_check_dsa(struct bpf_handle *bpf, __u32 dsa_switch, const char *dsa_proto, struct dsa_tag **dsa_tag) {
    size_t dsa_tag_sec_size;
    struct dsa_tag *dsa_tag_sec = bpf_get_section_data(bpf, DSA_TAG_SECTION, &dsa_tag_sec_size);
    if (!dsa_tag_sec)
        return BPFW_RC_ERROR;

    __s8 index = -1;
    for (int i = 0; i < dsa_tag_sec_size / sizeof(struct dsa_tag); i++) {
        if (strncmp(dsa_proto, dsa_tag_sec[i].proto, DSA_PROTO_MAX_LEN) == 0) {
            index = i;
            break;
        }
    }

    if (index == -1) {
        bpfw_error("Error: BPF program doesn't support the DSA tagging protocol '%s' of the DSA switch.\n",
            dsa_proto);

        return BPFW_RC_ERROR;
    }

    struct dsa_switch *dsa_switch_sec = bpf_get_section_data(bpf, DSA_SWITCH_SECTION, NULL);
    if (!dsa_switch_sec)
        return BPFW_RC_ERROR;

    dsa_switch_sec->ifindex = dsa_switch;
    dsa_switch_sec->proto   = index + 1;

    *dsa_tag = &dsa_tag_sec[index];

    return BPFW_RC_OK;
}


struct bpf_handle* bpf_open_object(const char *obj_path, enum bpfw_hook hook) {
    struct bpf_handle* bpf = (struct bpf_handle*)malloc(sizeof(struct bpf_handle));
    if (!bpf) {
        bpfw_error("Error allocating BPF handle: %s (-%d).\n", strerror(errno), errno);
        return NULL;
    }

    bpf->hook = hook;

    const char *load_prog, *unload_prog;
    if (hook & BPFW_HOOK_XDP) {
        load_prog   = XDP_PROG_NAME;
        unload_prog = TC_PROG_NAME;
    }
    else {
        load_prog   = TC_PROG_NAME;
        unload_prog = XDP_PROG_NAME;
    }

    // Try to open the BPF object file, return on error
    bpf->obj = bpf_object__open_file(obj_path, NULL);
    if (!bpf->obj) {
        bpfw_error("Error opening BPF object file %s: %s (-%d).\n", obj_path, strerror(errno), errno);
        goto free;
    }

    bpf->prog = bpf_object__find_program_by_name(bpf->obj, load_prog);
    if (!bpf->prog) {
        bpfw_error("Couldn't find %s BPF program in %s.\n", load_prog, obj_path);
        goto bpf_object__close;
    }

    struct bpf_program *bpf_unload_prog = bpf_object__find_program_by_name(bpf->obj, unload_prog);
    if (bpf_unload_prog)
        bpf_program__set_autoload(bpf_unload_prog, false);

    return bpf;

bpf_object__close:
    bpf_object__unpin_maps(bpf->obj, NULL);
    bpf_object__close(bpf->obj);

free:
    free(bpf);

    return NULL;
}

int bpf_load_program(struct bpf_handle* bpf) {
    // Try to load the BPF object into the kernel, return on error
    if (bpf_object__load(bpf->obj) != 0) {
        bpfw_error("Error loading BPF program into kernel: %s (-%d).\n", strerror(errno), errno);
        return BPFW_RC_ERROR;
    }

    return BPFW_RC_OK;
}

void bpf_unload_program(struct bpf_handle* bpf) {
    // Unpin the maps from /sys/fs/bpf
    bpf_object__unpin_maps(bpf->obj, NULL);
    bpf_object__close(bpf->obj);

    free(bpf);
}
