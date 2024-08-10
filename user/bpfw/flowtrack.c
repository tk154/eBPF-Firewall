#include "flowtrack.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpf/bpf.h>
#include <net/if.h>
#include <netinet/in.h>

#include "bpf_loader/bpf_loader.h"
#include "conntrack/conntrack.h"
#include "netlink/netlink.h"

#include "logging/logging.h"

#ifdef OPENWRT_UCODE
#include "ucode/ucode.h"
#endif


struct flowtrack_handle {
    enum bpfw_hook hook;

    int flow_map_fd;
    __u32 map_poll_sec;

    // Flow Timeouts
    __u32 tcp_flow_timeout;
    __u32 udp_flow_timeout;

    struct dsa_tag *dsa_tag;

    struct bpf_handle *bpf;
    struct netlink_handle *netlink_h;
    struct conntrack_handle *conntrack_h;

#ifdef OPENWRT_UCODE
    struct ucode_handle *ucode_h;
#endif
};

/*struct bpf_attach_args {
    struct bpf_handle* bpf;
    __u32 xdp_flags;
};*/


static void calc_l2_diff(struct flow_key_value *flow, struct flowtrack_handle *flowtrack_h) {
    enum bpfw_hook hook = flowtrack_h->hook;
    struct dsa_tag *tag = flowtrack_h->dsa_tag;
    __s8 diff = 0;
    
    if (flow->key.dsa_port)
        diff -= tag->rx_size;
    if (flow->value.next.hop.dsa_port)
        diff += tag->tx_size;

    if ((hook & BPFW_HOOK_XDP || flow->key.dsa_port) && flow->key.vlan_id)
        diff -= sizeof(struct vlanhdr);
    if ((hook & BPFW_HOOK_XDP || flow->value.next.hop.dsa_port) && flow->value.next.hop.vlan_id)
        diff += sizeof(struct vlanhdr);

    if (flow->key.pppoe_id)
        diff -= sizeof(struct pppoehdr);
    if (flow->value.next.hop.pppoe_id)
        diff += sizeof(struct pppoehdr);

	if ((hook & BPFW_HOOK_TC) && diff < 0) {
        bpfw_debug("TC cannot shrink L2 Header (L2 diff = %hhd).\n", diff);
        flow->value.action = ACTION_PASS;
    }
    else
        flow->value.next.hop.l2_diff = diff;
}


static int attach_bpf_program(struct bpf_handle* bpf, struct netlink_handle *netlink_h) {
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

            case BPFW_INTERFACE_DO_NOT_ATTACH:
                continue;
        }

        rc = bpf_ifindex_attach_program(bpf, iface->if_index);
        if (rc != BPFW_RC_OK) {
error:
            // If an error occured while attaching to one interface, detach all the already attached programs
            while (--iface >= ifaces)
                if (netlink_ifindex_should_attach(netlink_h, iface->if_index) == BPFW_INTERFACE_DO_ATTACH)
                    bpf_ifindex_detach_program(bpf, iface->if_index);

            break;
        }
    }

    // Retrieved interfaces are dynamically allocated, so they must be freed
    if_freenameindex(ifaces);

    return rc;
}

static int detach_bpf_program(struct bpf_handle* bpf, struct netlink_handle *netlink_h) {
    // Retrieve the name and index of all network interfaces
    struct if_nameindex* ifaces = if_nameindex();
    if (!ifaces) {
        bpfw_error("Error retrieving network interfaces: %s (-%d).\n", strerror(errno), errno);
        return BPFW_RC_ERROR;
    }

    for (struct if_nameindex* iface = ifaces; iface->if_index && iface->if_name; iface++)
        if (netlink_ifindex_should_attach(netlink_h, iface->if_index) == BPFW_INTERFACE_DO_ATTACH)
            bpf_ifindex_detach_program(bpf, iface->if_index);

    // Retrieved interfaces are dynamically allocated, so they must be freed
    if_freenameindex(ifaces);

    return BPFW_RC_OK;
}

static int new_bpf_interface(__u32 ifindex, void *data) {
    struct bpf_handle *bpf_h = data;

    return bpf_ifindex_attach_program(bpf_h, ifindex);
}


static int handle_bpf_entry(struct flowtrack_handle *flowtrack_h, struct flow_key_value *flow) {
    __u32 idle = flow->value.idle + flowtrack_h->map_poll_sec;

    if (flow->key.proto == IPPROTO_TCP && idle >= flowtrack_h->tcp_flow_timeout ||
        flow->key.proto == IPPROTO_UDP && idle >= flowtrack_h->udp_flow_timeout)
    {
        // Flow timeout occured, so delete it from the BPF map
        if (bpf_map_delete_elem(flowtrack_h->flow_map_fd, &flow->key) != 0) {
            bpfw_error("Error deleting flow entry: %s (-%d).\n", strerror(errno), errno);
            return BPFW_RC_ERROR;
        }

        return BPFW_RC_OK;
    }

    if (flow->value.action == ACTION_PASS || flow->value.action == ACTION_DROP)
        goto skip_lookup;

    switch (conntrack_lookup(flowtrack_h->conntrack_h, flow)) {
        case CONNECTION_NOT_FOUND:
#ifdef OPENWRT_UCODE
            if (flow->value.action == ACTION_NONE) {
                __u32 iif;

                int rc = netlink_get_route(flowtrack_h->netlink_h, flow, &iif);
                if (rc == BPFW_RC_ERROR)
                    return BPFW_RC_ERROR;

                if (rc == BPFW_RC_OK && flow->value.action != ACTION_DROP)
                    if (ucode_match_rule(flowtrack_h->ucode_h, flow, iif) == BPFW_RC_ERROR)
                        return BPFW_RC_ERROR;

                bpfw_debug_action("Act: ", flow->value.action);
            }
        break;
#endif

        case CONNECTION_NOT_ESTABLISHED:
            /* It could be possible that we have received the package here through the BPF map
            *  before it was processed by nf_conntrack, or it has been dropped
            */
            flow->value.action = ACTION_NONE;
        break;

        case CONNECTION_ESTABLISHED:
            if (flow->value.action == ACTION_NONE) {
                if (netlink_get_next_hop(flowtrack_h->netlink_h, flow) == BPFW_RC_ERROR)
                    return BPFW_RC_ERROR;

                if (flow->value.action == ACTION_REDIRECT)
                    calc_l2_diff(flow, flowtrack_h);

                bpfw_debug_action("Act: ", flow->value.action);
            }
        break;

        default:
            return BPFW_RC_ERROR;
    }

skip_lookup:
    flow->value.idle = idle;

    // Update the BPF flow entry, break out on error
    if (bpf_map_update_elem(flowtrack_h->flow_map_fd, &flow->key, &flow->value, BPF_EXIST) != 0) {
        bpfw_error("Error updating flow entry: %s (-%d).\n", strerror(errno), errno);
        return BPFW_RC_ERROR;
    }

    return BPFW_RC_OK;
}

int flowtrack_update(struct flowtrack_handle* flowtrack_h) {
    struct flow_key_value flow;

    // Retrieve the first key of the BPF flow map
    int rc = bpf_map_get_next_key(flowtrack_h->flow_map_fd, NULL, &flow.key);

    // Iterate through all the flow entries
    while (rc == 0) {
        // Retrieve the flow value of the current key
        if (bpf_map_lookup_elem(flowtrack_h->flow_map_fd, &flow.key, &flow.value) != 0) {
            bpfw_error("Error looking up flow entry: %s (-%d).\n", strerror(errno), errno);
            return BPFW_RC_ERROR;
        }

        if (handle_bpf_entry(flowtrack_h, &flow) != BPFW_RC_OK)
            return BPFW_RC_ERROR;

        // Retrieve the next key of the flows map
        rc = bpf_map_get_next_key(flowtrack_h->flow_map_fd, &flow.key, &flow.key);
    }

    if (rc != -ENOENT) {
        bpfw_error("Error retrieving flow key: %s (-%d).\n", strerror(errno), errno);
        return BPFW_RC_ERROR;
    }

    if (netlink_check_for_new_interfaces(flowtrack_h->netlink_h, new_bpf_interface, flowtrack_h->bpf) != BPFW_RC_OK)
        return BPFW_RC_ERROR;

    return 0;
}


struct flowtrack_handle* flowtrack_init(struct cmd_args *args) {
    struct flowtrack_handle* flowtrack_h = (struct flowtrack_handle*)malloc(sizeof(struct flowtrack_handle));
    if (!flowtrack_h) {
        bpfw_error("Error allocating flowtrack handle: %s (-%d).\n", strerror(errno), errno);
        return NULL;
    }

    flowtrack_h->map_poll_sec     = args->map_poll_sec;
    flowtrack_h->tcp_flow_timeout = args->tcp_flow_timeout;
    flowtrack_h->udp_flow_timeout = args->udp_flow_timeout;
    flowtrack_h->hook             = args->hook;

    bpfw_info("Initializing netlink ...\n");

    flowtrack_h->netlink_h = netlink_init(args->if_count == 0, args->dsa);
    if (!flowtrack_h->netlink_h)
        goto free;

    __u32 dsa_switch;
    char dsa_proto[DSA_PROTO_MAX_LEN];
    if (netlink_get_dsa(flowtrack_h->netlink_h, &dsa_switch, dsa_proto) != 0)
        goto netlink_destroy;

    bpfw_info("Opening BPF object ...\n");

    flowtrack_h->bpf = bpf_open_object(args->obj_path, args->hook);
    if (!flowtrack_h->bpf)
        goto netlink_destroy;

    if (args->dsa && bpf_check_dsa(flowtrack_h->bpf, dsa_switch, dsa_proto, &flowtrack_h->dsa_tag) != 0)
        goto bpf_unload_program;

    if (bpf_set_map_max_entries(flowtrack_h->bpf, FLOW_MAP_NAME, args->map_max_entries) != 0)
        goto bpf_unload_program;

    // Load the BPF object (including program and maps) into the kernel
    bpfw_info("Loading BPF program into kernel ...\n");

    if (bpf_load_program(flowtrack_h->bpf) != 0)
        goto bpf_unload_program;

    flowtrack_h->flow_map_fd = bpf_get_map_fd(flowtrack_h->bpf, FLOW_MAP_NAME);
    if (flowtrack_h->flow_map_fd < 0)
        goto bpf_unload_program;

    bpfw_info("Attaching BPF program to network interfaces ...\n");

    // Attach the program to the specified interface names
    int rc = args->if_count == 0 ? attach_bpf_program(flowtrack_h->bpf, flowtrack_h->netlink_h) :
        bpf_ifnames_attach_program(flowtrack_h->bpf, args->if_names, args->if_count);

    if (rc != 0)
        goto bpf_unload_program;

    bpfw_info("Initializing nf_conntrack ...\n");

    // Read the conntrack info and save it inside the BPF conntrack map
    flowtrack_h->conntrack_h = conntrack_init();
    if (!flowtrack_h->conntrack_h)
        goto bpf_detach_program;

#ifdef OPENWRT_UCODE
    bpfw_info("Initializing ucode ...\n");

    flowtrack_h->ucode_h = ucode_init();
    if (!flowtrack_h->ucode_h)
        goto conntrack_destroy;
#endif

    return flowtrack_h;

conntrack_destroy:
    // De-Init conntrack
    conntrack_destroy(flowtrack_h->conntrack_h);

bpf_detach_program:
    // Detach the program from the specified interface names
    args->if_count == 0 ? detach_bpf_program(flowtrack_h->bpf, flowtrack_h->netlink_h) :
        bpf_ifnames_detach_program(flowtrack_h->bpf, args->if_names, args->if_count);

bpf_unload_program:
    // Unload the BPF object from the kernel
    bpf_unload_program(flowtrack_h->bpf);

netlink_destroy:
    netlink_destroy(flowtrack_h->netlink_h);

free:
    free(flowtrack_h);

    return NULL;
}

void flowtrack_destroy(struct flowtrack_handle* flowtrack_h, struct cmd_args *args) {
#ifdef OPENWRT_UCODE
    // De-Init ucode
    ucode_destroy(flowtrack_h->ucode_h);
#endif

    // De-Init conntrack
    conntrack_destroy(flowtrack_h->conntrack_h);

    // Unload the BPF object from the kernel
    bpf_unload_program(flowtrack_h->bpf);

    // Detach the program from the specified interface names
    args->if_count == 0 ? attach_bpf_program(flowtrack_h->bpf, flowtrack_h->netlink_h) :
        bpf_ifnames_detach_program(flowtrack_h->bpf, args->if_names, args->if_count);

    // De-Init netlink
    netlink_destroy(flowtrack_h->netlink_h);

    free(flowtrack_h);
}
