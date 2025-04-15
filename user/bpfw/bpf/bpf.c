#include "bpf.h"

#include <errno.h>
#include <stdlib.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <net/if.h>
#include <linux/if_link.h>

#include "../log/log.h"


// Struct to keep BPF object and program pointers together
struct bpf_handle {
    struct bpf_object *obj;         // BPF object pointer

    struct map *iface_hooks;
    struct map *tc_opts;
    enum bpf_hook hook;
    
    int xdp_prog_fd, tc_prog_fd;    // BPF program file descriptors
    bool obj_loaded;
};

struct tc_opts {
    __u32 handle, priority;
};


static __u32 get_xdp_flag(enum bpf_hook hook) {
    switch (hook) {
        case BPF_HOOK_XDP_GENERIC:
            return XDP_FLAGS_SKB_MODE;
        case BPF_HOOK_XDP_NATIVE:
            return XDP_FLAGS_DRV_MODE;
        case BPF_HOOK_XDP_OFFLOAD:
            return XDP_FLAGS_HW_MODE;
        default:
            return 0;
    }
}

static const char *get_xdp_str(__u32 xdp_flag) {
    switch (xdp_flag) {
        case XDP_FLAGS_HW_MODE:
            return "XDP Offload";
        case XDP_FLAGS_DRV_MODE:
            return "XDP Native";
        case XDP_FLAGS_SKB_MODE:
            return "XDP Generic";
        default:
            return "XDP";
    }
}


static void libbpf_enable_messages(libbpf_print_fn_t fn) {
    libbpf_set_print(fn);
}

static libbpf_print_fn_t libbpf_disable_messages() {
    return libbpf_set_print(NULL);
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

static int bpf_get_program_fd(struct bpf_object *obj, const char *prog_name) {
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, prog_name);
    return prog ? bpf_program__fd(prog) : -1;
}

static int bpf_load_object(struct bpf_handle *bpf) {
    // Try to load the BPF object into the kernel, return on error
    if (bpf_object__load(bpf->obj) != 0) {
        bpfw_error("Error loading BPF program into kernel: %s (-%d).\n",
            strerror(errno), errno);
        return BPFW_RC_ERROR;
    }

    bpf->obj_loaded  = true;
    bpf->xdp_prog_fd = bpf_get_program_fd(bpf->obj, XDP_PROG_NAME);
    bpf->tc_prog_fd  = bpf_get_program_fd(bpf->obj, TC_PROG_NAME);

    if (bpf->xdp_prog_fd < 0 && bpf->tc_prog_fd < 0) {
        bpfw_error("XDP and TC program not found inside the BPF object file.\n");
        return BPFW_RC_ERROR;
    }

    return BPFW_RC_OK;
}


static int bpf_attach_xdp_program(struct bpf_handle *bpf, __u32 ifindex, __u32 xdp_flag, bool try) {
    const char *xdp_str = get_xdp_str(xdp_flag);
    libbpf_print_fn_t fn;
    int rc;

    if (try)
        fn = libbpf_disable_messages();

    // Attach the program to the XDP hook
    if (bpf_xdp_attach(ifindex, bpf->xdp_prog_fd, xdp_flag, NULL) != 0) {
        if (try && (errno == EOPNOTSUPP || xdp_flag == XDP_FLAGS_HW_MODE && errno == EINVAL))
            rc = EOPNOTSUPP;
        else {
            bpfw_error_ifindex("Error attaching %s program to ", ifindex, errno, xdp_str);
            rc = BPFW_RC_ERROR;
        }
    }
    else {
        bpfw_debug_ifindex("  Attached %s hook to ", ifindex, 0, xdp_str);
        rc = BPFW_RC_OK;
    }

    if (try)
        libbpf_enable_messages(fn);

    return rc;
}

static int bpf_attach_tc_program(struct bpf_handle *bpf, __u32 ifindex) {
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex, .attach_point = BPF_TC_INGRESS);
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts, .prog_fd = bpf->tc_prog_fd);
    libbpf_print_fn_t fn = libbpf_disable_messages();
    struct tc_opts tc;
    int rc;

    // Create a TC hook on the ingress of the interface
    // bpf_tc_hook_create will return an error and print an error message if the hook already exists
    rc = bpf_tc_hook_create(&hook);
    libbpf_enable_messages(fn);

    if (rc != 0 && rc != -EEXIST) {
        bpfw_errno("Error creating TC hook", errno);
        return BPFW_RC_ERROR;
    }

    // Attach the TC prgram to the created hook
    if (bpf_tc_attach(&hook, &opts) != 0) {
        bpfw_error_ifindex("Error attaching TC program to ",
            ifindex, errno);
        return BPFW_RC_ERROR;
    }

    tc.handle = opts.handle;
    tc.priority = opts.priority;

    rc = map_insert_entry(bpf->tc_opts, &ifindex, &tc);
    if (rc != 0) {
        bpfw_error_ifindex("Error creating new tc_opts map entry for ",
            ifindex, rc);

        bpf_tc_detach(&hook, &opts);
        return BPFW_RC_ERROR;
    }

    bpfw_debug_ifindex("  Attached TC hook to ", ifindex, 0);

    return BPFW_RC_OK;
}

static void bpf_detach_xdp_program(struct bpf_handle *bpf, __u32 ifindex, __u32 xdp_flag) {
    // Detach the program from the XDP hook
    bpf_xdp_detach(ifindex, xdp_flag, NULL);
}

static void bpf_detach_tc_program(struct bpf_handle *bpf, __u32 ifindex) {
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex, .attach_point = BPF_TC_INGRESS);
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts);
    struct tc_opts tc;
    int rc;

    rc = map_lookup_entry(bpf->tc_opts, &ifindex, &tc);
    if (rc != 0) {
        bpfw_error_ifindex("Error looking up tc_opts map entry for ",
            ifindex, rc);
        return;
    }

    opts.handle = tc.handle;
    opts.priority = tc.priority;

    // Detach the TC prgram
    bpf_tc_detach(&hook, &opts);
    map_delete_entry(bpf->tc_opts, &ifindex);
}

static int bpf_attach_program_auto(struct bpf_handle *bpf, __u32 ifindex) {
    int rc;

    if (bpf->xdp_prog_fd >= 0) {
        rc = bpf_attach_xdp_program(bpf, ifindex, XDP_FLAGS_HW_MODE, true);
        if (rc != EOPNOTSUPP)
            return rc;

        rc = bpf_attach_xdp_program(bpf, ifindex, XDP_FLAGS_DRV_MODE, true);
        if (rc != EOPNOTSUPP)
            return rc;
    }

    if (bpf->tc_prog_fd >= 0)
        return bpf_attach_tc_program(bpf, ifindex);

    return bpf_attach_xdp_program(bpf, ifindex, XDP_FLAGS_SKB_MODE, false);
}

static void bpf_detach_program_auto(struct bpf_handle *bpf, __u32 ifindex) {
    __u32 prod_id;

    bpf_xdp_query_id(ifindex, 0, &prod_id) ?
        bpf_detach_tc_program(bpf, ifindex) :
        bpf_detach_xdp_program(bpf, ifindex, 0);
}


static int bpf_ifindex_attach_program(struct bpf_handle* bpf, __u32 ifindex, enum bpf_hook hook, bool try) {
    if (hook == BPF_HOOK_AUTO)
        return bpf_attach_program_auto(bpf, ifindex);

    if (hook & BPF_HOOK_XDP) {
        if (bpf->xdp_prog_fd < 0) {
            bpfw_error("XDP program not found inside the BPF object file.\n");
            return BPFW_RC_ERROR;
        }

        return bpf_attach_xdp_program(bpf, ifindex, get_xdp_flag(hook), try);
    }

    if (bpf->tc_prog_fd < 0) {
        bpfw_error("TC program not found inside the BPF object file.\n");
        return BPFW_RC_ERROR;
    }

    return bpf_attach_tc_program(bpf, ifindex);
}

static void bpf_ifindex_detach_program(struct bpf_handle* bpf, __u32 ifindex, enum bpf_hook hook) {
    if (hook == BPF_HOOK_AUTO)
        return bpf_detach_program_auto(bpf, ifindex);

    if (hook & BPF_HOOK_XDP)
        return bpf_detach_xdp_program(bpf, ifindex, get_xdp_flag(hook));

    return bpf_detach_tc_program(bpf, ifindex);
}

static int bpf_ifname_attach_program(struct bpf_handle* bpf, char* ifname, enum bpf_hook hook, bool try) {
    // Get the interface index from the interface name
    __u32 ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        bpfw_error("Error finding network interface %s: %s (-%d).\n",
            ifname, strerror(errno), errno);
        return BPFW_RC_ERROR;
    }

    return bpf_ifindex_attach_program(bpf, ifindex, hook, try);
}

static int bpf_ifname_detach_program(struct bpf_handle* bpf, char* ifname, enum bpf_hook hook) {
    // Get the interface index from the interface name
    __u32 ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        bpfw_error("Error finding network interface %s: %s (-%d).\n",
            ifname, strerror(errno), errno);
        return BPFW_RC_ERROR;
    }

    bpf_ifindex_detach_program(bpf, ifindex, hook);
    return BPFW_RC_OK;
}


static void bpf_auto_attach_error(struct bpf_handle *bpf, struct netlink_handle *netlink,
                                 struct if_nameindex *ifaces, struct if_nameindex *iface) {
    enum bpf_hook hook;

    // If an error occured while attaching to one interface, detach all the already attached programs
    while (--iface >= ifaces) {
        if (map_lookup_entry(bpf->iface_hooks, iface->if_name, &hook) == 0)
            continue;

        if (netlink_ifindex_should_attach(netlink, iface->if_index) == NL_INTERFACE_DO_ATTACH)
            bpf_ifindex_detach_program(bpf, iface->if_index, bpf->hook);
    }
}

static int bpf_auto_attach_program(struct bpf_handle *bpf, struct netlink_handle *netlink) {
    // Retrieve the name and index of all network interfaces
    struct if_nameindex *iface, *ifaces = if_nameindex();
    int rc = BPFW_RC_OK;
    enum bpf_hook hook;

    if (!ifaces) {
        bpfw_error("Error retrieving network interfaces: %s (-%d).\n",
            strerror(errno), errno);
        return BPFW_RC_ERROR;
    }

    for (iface = ifaces; iface->if_index && iface->if_name; iface++) {
        if (map_lookup_entry(bpf->iface_hooks, iface->if_name, &hook) == 0)
            continue;

        rc = netlink_ifindex_should_attach(netlink, iface->if_index);
        switch (rc) {
            case BPFW_RC_ERROR:
                bpf_auto_attach_error(bpf, netlink, iface, ifaces);
                goto free;

            case NL_INTERFACE_DO_NOT_ATTACH:
                continue;
        }

        rc = bpf_ifindex_attach_program(bpf, iface->if_index, bpf->hook, true);
        switch (rc) {
            case BPFW_RC_ERROR:
                bpf_auto_attach_error(bpf, netlink, iface, ifaces);
                goto free;

            case EOPNOTSUPP:
                bpfw_warn("Warning: %s doesn't support %s.\n",
                    iface->if_name, get_xdp_str(get_xdp_flag(bpf->hook)));
        }
    }

free:
    // Retrieved interfaces are dynamically allocated, so they must be freed
    if_freenameindex(ifaces);

    return rc;
}

static int bpf_manual_attach_program(struct bpf_handle *bpf) {
    char ifname[IF_NAMESIZE];
    enum bpf_hook hook;
    int rc;

    map_for_each_entry(bpf->iface_hooks, ifname, &hook, {
        rc = bpf_ifname_attach_program(bpf, ifname, hook, false);

        if (rc != BPFW_RC_OK) {
            // If an error occured while attaching to one interface, detach all the already attached programs
            while (map_prev_entry(bpf->iface_hooks, ifname, &hook) == 0)
                bpf_ifname_detach_program(bpf, ifname, hook);

            return rc;
        }
    });

    return BPFW_RC_OK;
}

static int bpf_auto_detach_program(struct bpf_handle *bpf, struct netlink_handle *netlink) {
    // Retrieve the name and index of all network interfaces
    struct if_nameindex *iface, *ifaces = if_nameindex();
    enum bpf_hook hook;

    if (!ifaces) {
        bpfw_error("Error retrieving network interfaces: %s (-%d).\n",
            strerror(errno), errno);
        return BPFW_RC_ERROR;
    }

    for (iface = ifaces; iface->if_index && iface->if_name; iface++) {
        if (map_lookup_entry(bpf->iface_hooks, iface->if_name, &hook) == 0)
            continue;

        if (netlink_ifindex_should_attach(netlink, iface->if_index) == NL_INTERFACE_DO_ATTACH)
            bpf_ifindex_detach_program(bpf, iface->if_index, bpf->hook);
    }

    // Retrieved interfaces are dynamically allocated, so they must be freed
    if_freenameindex(ifaces);

    return BPFW_RC_OK;
}

static void bpf_manual_detach_program(struct bpf_handle *bpf) {
    char ifname[IF_NAMESIZE];
    enum bpf_hook hook;

    map_for_each_entry(bpf->iface_hooks, ifname, &hook, {
        bpf_ifname_detach_program(bpf, ifname, hook);
    });
}


int bpf_attach_program(struct bpf_handle *bpf, struct netlink_handle *netlink, bool auto_attach) {
    if (!bpf->obj_loaded && bpf_load_object(bpf) != BPFW_RC_OK)
        goto error;

    if (bpf_manual_attach_program(bpf) != BPFW_RC_OK)
        goto error;

    if (auto_attach && bpf_auto_attach_program(bpf, netlink) != BPFW_RC_OK)
        goto bpf_manual_detach_program;

    return BPFW_RC_OK;

bpf_manual_detach_program:
    bpf_manual_detach_program(bpf);

error:
    return BPFW_RC_ERROR;
}

void bpf_detach_program(struct bpf_handle *bpf, struct netlink_handle *netlink, bool auto_attach) {
    bpf_manual_detach_program(bpf);

    if (auto_attach)
        bpf_auto_detach_program(bpf, netlink);
}

int bpf_iface_attach_program(struct bpf_handle *bpf, struct netlink_handle *nl, __u32 ifindex, const char *ifname) {
    enum bpf_hook hook = bpf->hook;
    int rc;

    map_lookup_entry(bpf->iface_hooks, ifname, &hook);

    if (!bpf->obj_loaded && bpf_load_object(bpf) != BPFW_RC_OK)
        return BPFW_RC_ERROR;

    rc = netlink_ifindex_should_attach(nl, ifindex);
    switch (rc) {
        case NL_INTERFACE_DO_NOT_ATTACH:
            return BPFW_RC_OK;

        case NL_INTERFACE_DO_ATTACH:
            return bpf_ifindex_attach_program(bpf, ifindex, hook, true);

        default:
            return rc;
    }
}

int bpf_iface_detach_program(struct bpf_handle* bpf, struct netlink_handle *nl, __u32 ifindex, const char *ifname) {
    enum bpf_hook hook = bpf->hook;
    int rc;

    map_lookup_entry(bpf->iface_hooks, ifname, &hook);

    rc = netlink_ifindex_should_attach(nl, ifindex);
    switch (rc) {
        case NL_INTERFACE_DO_ATTACH:
            bpf_ifindex_detach_program(bpf, ifindex, hook);

        case NL_INTERFACE_DO_NOT_ATTACH:
            return BPFW_RC_OK;

        default:
            return rc;
    }
}


struct bpf_map bpf_get_map(struct bpf_handle *bpf, const char *map_name) {
    struct bpf_map map;

    // Get the file descriptor of the BPF flow map
    map.fd = bpf_object__find_map_fd_by_name(bpf->obj, map_name);
    if (map.fd < 0) {
        bpfw_error("Error: Couldn't find BPF map %s.\n", map_name);
        map.name = NULL;
    }
    else
        map.name = map_name;

    return map;
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


int bpf_map_lookup_entry(struct bpf_map *map, const void *key, void *value) {
    if (bpf_map_lookup_elem(map->fd, key, value) != 0) {
        bpfw_error("Error looking up '%s' map entry: %s (-%d).\n",
            map->name, strerror(errno), errno);
        return BPFW_RC_ERROR;
    }

    return BPFW_RC_OK;
}

int bpf_map_update_entry(struct bpf_map *map, const void *key, const void *value) {
    // Update the BPF entry
    if (bpf_map_update_elem(map->fd, key, value, BPF_EXIST) != 0) {
        bpfw_error("Error updating '%s' map entry: %s (-%d).\n",
            map->name, strerror(errno), errno);
        return BPFW_RC_ERROR;
    }

    return BPFW_RC_OK;
}

int bpf_map_delete_entry(struct bpf_map *map, const void *key) {
    if (bpf_map_delete_elem(map->fd, key) != 0) {
        bpfw_error("Error deleting '%s' map entry: %s (-%d).\n",
            map->name, strerror(errno), errno);
        return BPFW_RC_ERROR;
    }

    return BPFW_RC_OK;
}


static int __bpf_map_next_entry(struct bpf_map *map, const void *key, void *next_key, void *value) {
    int rc = bpf_map_get_next_key(map->fd, key, next_key);

    switch (rc) {
        case 0:
            return bpf_map_lookup_entry(map, next_key, value);

        case -ENOENT:
            return -EOF;

        default:
            bpfw_error("Error retrieving '%s' map key: %s (-%d).\n",
                map->name, strerror(errno), errno);
            return BPFW_RC_ERROR;
    }
}

int bpf_map_first_entry(struct bpf_map *map, void *key, void *value) {
    return __bpf_map_next_entry(map, NULL, key, value);
}

int bpf_map_next_entry(struct bpf_map *map, void *key, void *value) {
    return __bpf_map_next_entry(map, key, key, value);
}


struct bpf_handle* bpf_init(const char *obj_path, struct map *iface_hooks, enum bpf_hook hook) {
    struct bpf_handle* bpf = malloc(sizeof(struct bpf_handle));
    if (!bpf) {
        bpfw_error("Error allocating BPF handle: %s (-%d).\n",
            strerror(errno), errno);
        goto error;
    }

    bpf->obj_loaded = false;
    bpf->tc_opts = map_create(sizeof(__u32), sizeof(struct tc_opts));

    bpf->iface_hooks = iface_hooks;
    bpf->hook = hook;

    // Try to open the BPF object file, return on error
    bpf->obj = bpf_object__open_file(obj_path, NULL);
    if (!bpf->obj) {
        bpfw_error("Error opening BPF object file %s: %s (-%d).\n",
            obj_path, strerror(errno), errno);
        goto free;
    }

    return bpf;

free:
    free(bpf);
error:
    return NULL;
}

void bpf_destroy(struct bpf_handle* bpf) {
    // Unpin the maps from /sys/fs/bpf
    bpf_object__unpin_maps(bpf->obj, NULL);
    bpf_object__close(bpf->obj);

    map_delete(bpf->tc_opts);

    free(bpf);
}
