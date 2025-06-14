#include "bpf_common.h"

#include <errno.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <linux/if_link.h>

#include "../netlink/netlink.h"
#include "../map/map.h"


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
    __u32 prog_id = 0;

    bpf_xdp_query_id(ifindex, 0, &prog_id);
    prog_id ? bpf_detach_xdp_program(bpf, ifindex, 0) :
        bpf_detach_tc_program(bpf, ifindex);
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
