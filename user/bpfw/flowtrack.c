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

#include "common_user.h"

#ifdef OPENWRT_UCODE
#include "ucode/ucode.h"
#endif


struct flowtrack_handle {
    unsigned int map_poll_sec;

    enum bpfw_hook hook;
    int flow_map_fd;

    bool dsa;
    struct dsa_tag *dsa_tag;

    struct bpf_handle *bpf;
    struct netlink_handle *netlink_h;
    struct conntrack_handle *conntrack_h;

#ifdef OPENWRT_UCODE
    struct ucode_handle *ucode_h;
#endif

    // Flow Timeouts
    unsigned int tcp_flow_timeout;
    unsigned int udp_flow_timeout;
};

/*struct bpf_attach_args {
    struct bpf_handle* bpf;
    __u32 xdp_flags;
};*/


static void calc_l2_diff(struct flow_key_value *flow, enum bpfw_hook hook, struct dsa_tag *dsa_tag) {
    __s8 diff = 0;
    
    if (flow->key.dsa_port)
        diff -= dsa_tag->rx_size;
    else
        diff -= sizeof(struct ethhdr);
    
    if (flow->value.next_h.dsa_port)
        diff += dsa_tag->tx_size;
    else
        diff += sizeof(struct ethhdr);

    if ((hook & BPFW_HOOK_XDP || flow->key.dsa_port) && flow->key.vlan_id)
        diff -= sizeof(struct vlanhdr);
    if ((hook & BPFW_HOOK_XDP || flow->value.next_h.dsa_port) && flow->value.next_h.vlan_id)
        diff += sizeof(struct vlanhdr);

    if (flow->key.pppoe_id)
        diff -= sizeof(struct pppoehdr);
    if (flow->value.next_h.pppoe_id)
        diff += sizeof(struct pppoehdr);

	if ((hook & BPFW_HOOK_TC) && diff < 0) {
        bpfw_debug("TC cannot shrink L2 Header (L2 diff = %hhd).\n", diff);
        flow->value.action = ACTION_PASS;
    }
    else
        flow->value.next_h.l2_diff = diff;
}

static int attach_bpf_program(struct bpf_handle* bpf, struct netlink_handle *netlink_h, bool dsa) {
    // Retrieve the name and index of all network interfaces
    struct if_nameindex* ifaces = if_nameindex();
    if (!ifaces) {
        fprintf(stderr, "Error retrieving network interfaces: %s (-%d).\n", strerror(errno), errno);
        return -1;
    }

    int rc = 0;
    for (struct if_nameindex* iface = ifaces; iface->if_index && iface->if_name; iface++) {
        rc = netlink_ifindex_should_attach(netlink_h, iface->if_index, dsa);
        if (rc < 0)
            goto error;

        if (rc == 0)
            continue;

        rc = bpf_ifindex_attach_program(bpf, iface->if_index);
        if (rc != 0) {
error:
            // If an error occured while attaching to one interface, detach all the already attached programs
            while (--iface >= ifaces)
                if (netlink_ifindex_should_attach(netlink_h, iface->if_index, dsa) == 1)
                    bpf_ifindex_detach_program(bpf, iface->if_index);

            break;
        }
    }

    // Retrieved interfaces are dynamically allocated, so they must be freed
    if_freenameindex(ifaces);

    return rc;
}

static int detach_bpf_program(struct bpf_handle* bpf, struct netlink_handle *netlink_h, bool dsa) {
    // Retrieve the name and index of all network interfaces
    struct if_nameindex* ifaces = if_nameindex();
    if (!ifaces) {
        fprintf(stderr, "Error retrieving network interfaces: %s (-%d).\n", strerror(errno), errno);
        return -1;
    }

    for (struct if_nameindex* iface = ifaces; iface->if_index && iface->if_name; iface++)
        if (netlink_ifindex_should_attach(netlink_h, iface->if_index, dsa) == 1)
            bpf_ifindex_detach_program(bpf, iface->if_index);

    // Retrieved interfaces are dynamically allocated, so they must be freed
    if_freenameindex(ifaces);

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
    flowtrack_h->dsa              = args->dsa;

    bpfw_info("Initializing netlink ...\n");

    flowtrack_h->netlink_h = netlink_init();
    if (!flowtrack_h->netlink_h)
        goto free;

    // Load the BPF object (including program and maps) into the kernel
    bpfw_info("Loading BPF program into kernel ...\n");

    flowtrack_h->bpf = bpf_load_program(args->prog_path, args->hook, args->dsa);
    if (!flowtrack_h->bpf)
        goto netlink_destroy;

    flowtrack_h->flow_map_fd = bpf_get_map_fd(flowtrack_h->bpf, FLOW_MAP_NAME);
    if (flowtrack_h->flow_map_fd < 0)
        goto bpf_unload_program;

    if (flowtrack_h->dsa) {
        flowtrack_h->dsa_tag = bpf_get_section_data(flowtrack_h->bpf, DSA_TAG_SECTION, NULL);
        if (!flowtrack_h->dsa_tag)
            goto bpf_unload_program;
    }

    bpfw_info("Attaching BPF program to network interfaces ...\n");

    // Attach the program to the specified interface names
    int rc = args->if_count == 0 ? attach_bpf_program(flowtrack_h->bpf, flowtrack_h->netlink_h, args->dsa) :
        bpf_ifnames_attach_program(flowtrack_h->bpf, args->if_names, args->if_count);

    if (rc != 0)
        goto bpf_unload_program;

    bpfw_info("Initializing nf_conntrack ...\n");

    // Read the conntrack info and save it inside the BPF conntrack map
    flowtrack_h->conntrack_h = conntrack_init();
    if (!flowtrack_h->conntrack_h)
        goto bpf_ifs_detach_program;

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

bpf_ifs_detach_program:
    // Detach the program from the specified interface names
    args->if_count == 0 ? detach_bpf_program(flowtrack_h->bpf, flowtrack_h->netlink_h, args->dsa) :
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

int flowtrack_update(struct flowtrack_handle* flowtrack_h) {
    struct flow_key_value flow;

    // Retrieve the first key of the BPF flow map
    int bpf_rc = bpf_map_get_next_key(flowtrack_h->flow_map_fd, NULL, &flow.key);

    // Iterate through all the flow entries
    while (bpf_rc == 0) {
        // Retrieve the flow value of the current key
        if (bpf_map_lookup_elem(flowtrack_h->flow_map_fd, &flow.key, &flow.value) != 0) {
            bpfw_error("Error looking up flow entry: %s (-%d).\n", strerror(errno), errno);
            return -1;
        }

        __u32 idle = flow.value.idle + flowtrack_h->map_poll_sec;

        if (flow.key.proto == IPPROTO_TCP && idle >= flowtrack_h->tcp_flow_timeout ||
            flow.key.proto == IPPROTO_UDP && idle >= flowtrack_h->udp_flow_timeout)
        {
            // Flow timeout occured, so delete it from the BPF map
            if (bpf_map_delete_elem(flowtrack_h->flow_map_fd, &flow.key) != 0) {
                bpfw_error("Error deleting flow entry: %s (-%d).\n", strerror(errno), errno);
                return -1;
            }

            goto get_next_key;
        }

        switch (conntrack_lookup(flowtrack_h->conntrack_h, &flow)) {
            case CONNECTION_NOT_FOUND:
#ifdef OPENWRT_UCODE
                if (flow.value.action == ACTION_NONE) {
                    if (netlink_get_route(flowtrack_h->netlink_h, &flow) != 0)
                        return -1;

                    if (flow.value.action != ACTION_DROP)
                        if (ucode_match_rule(flowtrack_h->ucode_h, &flow) != 0)
                            return -1;
                }
            break;
#endif

            case CONNECTION_NOT_ESTABLISHED:
                /* It could be possible that we have received the package here through the BPF map
                *  before it was processed by nf_conntrack, or it has been dropped
                */
                flow.value.action = ACTION_NONE;
            break;

            case CONNECTION_ESTABLISHED:
                if (flow.value.action == ACTION_NONE) {
                    if (netlink_get_next_hop(flowtrack_h->netlink_h, &flow, flowtrack_h->dsa) != 0)
                        return -1;

                    if (flow.value.action == ACTION_REDIRECT)
                        calc_l2_diff(&flow, flowtrack_h->hook, flowtrack_h->dsa_tag);

                    bpfw_debug_action("Act: ", flow.value.action);
                }
            break;

            default:
                return -1;
        }

        flow.value.idle = idle;

        // Update the BPF flow entry, break out on error
        if (bpf_map_update_elem(flowtrack_h->flow_map_fd, &flow.key, &flow.value, BPF_EXIST) != 0) {
            bpfw_error("Error updating flow entry: %s (-%d).\n", strerror(errno), errno);
            return -1;
        }

get_next_key:
        // Retrieve the next key of the flows map
        bpf_rc = bpf_map_get_next_key(flowtrack_h->flow_map_fd, &flow.key, &flow.key);
    }

    if (bpf_rc != -ENOENT) {
        bpfw_error("Error retrieving flow key: %s (-%d).\n", strerror(errno), errno);
        return -1;
    }

    return 0;
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
    args->if_count == 0 ? detach_bpf_program(flowtrack_h->bpf, flowtrack_h->netlink_h, args->dsa) :
        bpf_ifnames_detach_program(flowtrack_h->bpf, args->if_names, args->if_count);

    // De-Init netlink
    netlink_destroy(flowtrack_h->netlink_h);

    free(flowtrack_h);
}
