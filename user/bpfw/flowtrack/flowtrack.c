#include "flowtrack.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <bpf/bpf.h>
#include <net/if.h>
#include <netinet/in.h>

#include "../bpf_loader/bpf_loader.h"
#include "../conntrack/conntrack.h"
#include "../netlink/netlink.h"

#include "../logging/logging.h"

#ifdef OPENWRT_UCODE
#include "../ucode/ucode.h"
#endif


struct flowtrack_handle {
    enum bpfw_hook hook;
    __u32 map_poll_sec;

    struct {
        int flow, user_time;
    } map_fd;

    // Flow Timeouts
    struct flow_timeout flow_timeout;
    struct dsa_tag *dsa_tag;

    struct {
        struct bpf_handle *bpf;
        struct netlink_handle *netlink;
        struct conntrack_handle *conntrack;
    } handle;

#ifdef OPENWRT_UCODE
    struct ucode_handle *ucode_h;
#endif
};


static __u64 time_get_coarse_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_COARSE, &ts);

    return ts.tv_sec * (__u64)1e9 + ts.tv_nsec;
}

static int update_userspace_time(struct flowtrack_handle *flowtrack_h, __u64 curr_time) {
    unsigned int index = 0;

    struct user_time user = {
        .timeout = 3 * flowtrack_h->map_poll_sec * (__u64)1e9, .last_time = curr_time
    };

    // Update the BPF flow entry, break out on error
    if (bpf_map_update_elem(flowtrack_h->map_fd.user_time, &index, &user, BPF_EXIST) != 0) {
        bpfw_error("Error updating BPF userspace time: %s (-%d).\n", strerror(errno), errno);
        return BPFW_RC_ERROR;
    }

    return BPFW_RC_OK;
}


static int calc_l2_diff(struct flowtrack_handle *flowtrack_h, struct flow_key_value *flow) {
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
        return 1;
    }

    flow->value.next.hop.l2_diff = diff;

    return BPFW_RC_OK;
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

static int detach_bpf_program(struct bpf_handle* bpf, struct netlink_handle *netlink_h) {
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

static int update_bpf_entry(int map_fd, struct flow_key_value *flow) {
    // Update the BPF flow entry, break out on error
    if (bpf_map_update_elem(map_fd, &flow->key, &flow->value, BPF_EXIST) != 0) {
        bpfw_error("Error updating flow entry: %s (-%d).\n", strerror(errno), errno);
        return BPFW_RC_ERROR;
    }

    return BPFW_RC_OK;
}

static int delete_bpf_entry(int map_fd, void *key) {
    if (bpf_map_delete_elem(map_fd, key) != 0) {
        bpfw_error("Error deleting flow entry: %s (-%d).\n", strerror(errno), errno);
        return BPFW_RC_ERROR;
    }

    return BPFW_RC_OK;
}

static int new_bpf_interface(__u32 ifindex, void *data) {
    struct flowtrack_handle *flowtrack_h = data;

    return bpf_ifindex_attach_program(flowtrack_h->handle.bpf, ifindex);
}


static int connection_not_found(struct flowtrack_handle *flowtrack_h, struct flow_key_value *flow) {
    /* It could be possible that we have received the package here through the BPF map
    *  before it was processed by nf_conntrack, or it has been dropped
    */

    if (flow->value.action != ACTION_NONE)
        return BPFW_RC_OK;

    bpfw_debug_key("\nNon: ", &flow->key);

    int rc = netlink_get_route(flowtrack_h->handle.netlink, flow);
    switch (rc) {
        case BPFW_RC_ERROR:
            return BPFW_RC_ERROR;

        case ACTION_REDIRECT:
            flow->value.action = ACTION_PASS_TEMP;
            break;

        default:
            flow->value.action = rc;
    }

#ifdef OPENWRT_UCODE
    if (rc != ACTION_DROP &&
        ucode_match_rule(flowtrack_h->ucode_h, flow) != BPFW_RC_OK)
            return BPFW_RC_ERROR;
#endif

    bpfw_debug_action("Act: ", flow->value.action);

    return BPFW_RC_OK;
}

static void connection_flowtable_offload(struct flow_key_value *flow) {
    if (flow->value.action == ACTION_NONE)
        bpfw_debug_key("\nConnection is offloaded to flowtable. Cannot read TCP state.\n", &flow->key);
}

static int connection_not_established(struct flow_value *f_value) {
    f_value->action = ACTION_PASS_TEMP;

    return BPFW_RC_OK;
}

static int connection_established(struct flowtrack_handle *flowtrack_h, struct flow_key_value *flow, __u32 last_packet_sec_ago) {
    switch (flow->value.action) {
        case ACTION_PASS_TEMP:
            memset(&flow->value.next, 0, sizeof(flow->value.next));

        case ACTION_NONE:
            bpfw_debug_key("\nCon: ", &flow->key);

            // Since the TTL is decremented, we must increment the checksum for IPv4
            if (flow->key.family == AF_INET)
                flow->value.next.ipv4_cksum_diff = htons(0x0100);

            // Check for NAT
            conntrack_check_nat(flowtrack_h->handle.conntrack, flow);
            
            int rc = netlink_get_next_hop(flowtrack_h->handle.netlink, flow);
            switch (rc) {
                case BPFW_RC_ERROR:
                    return BPFW_RC_ERROR;

                case ACTION_REDIRECT:
                    if (calc_l2_diff(flowtrack_h, flow) != BPFW_RC_OK) {
                        flow->value.action = ACTION_PASS;
                        break;
                    }

                default:
                    flow->value.action = rc;
            }
            
            bpfw_debug_action("Act: ", flow->value.action);
            break;

        case ACTION_REDIRECT:
            // If there was a new package, update the nf_conntrack timeout
            if (last_packet_sec_ago < flowtrack_h->map_poll_sec &&
                conntrack_update_timeout(flowtrack_h->handle.conntrack) != BPFW_RC_OK)
                    return BPFW_RC_ERROR;
    }

    return BPFW_RC_OK;
}


static int handle_bpf_entry(struct flowtrack_handle *flowtrack_h, struct flow_key_value *flow, __u32 time_sec) {
    __u32 flow_time_sec = flow->value.time / (__u64)1e9;
    __u32 flow_timeout = flow->key.proto == IPPROTO_TCP ?
        flowtrack_h->flow_timeout.tcp : flowtrack_h->flow_timeout.udp;

    __u32 last_packet_sec_ago = time_sec - flow_time_sec;
    if (last_packet_sec_ago >= flow_timeout)
        // Flow timeout occured, so delete it from the BPF map
        return delete_bpf_entry(flowtrack_h->map_fd.flow, &flow->key);

    __u8 action = flow->value.action;
    if (action == ACTION_DROP)
        return BPFW_RC_OK;

    int rc = conntrack_do_lookup(flowtrack_h->handle.conntrack, flow);
    switch (rc) {
        case CT_CONN_NOT_FOUND:
            rc = connection_not_found(flowtrack_h, flow);
            break;

        case CT_CONN_FLOWTABLE_OFFLOAD:
            connection_flowtable_offload(flow);

        case CT_CONN_NOT_ESTABLISHED:
            rc = connection_not_established(&flow->value);
            break;

        case CT_CONN_ESTABLISHED:
            rc = connection_established(flowtrack_h, flow, last_packet_sec_ago);
            conntrack_free_ct_entry(flowtrack_h->handle.conntrack);
            break;

        default:
            return BPFW_RC_ERROR;
    }

    if (rc != BPFW_RC_OK || action == flow->value.action)
        return rc;

    return update_bpf_entry(flowtrack_h->map_fd.flow, flow);
}

int flowtrack_update(struct flowtrack_handle* flowtrack_h) {
    struct flow_key_value flow;

    __u64 time_ns  = time_get_coarse_ns();
    __u32 time_sec = time_ns / (__u64)1e9;

    // Iterate through all the flow entries
    bpf_flow_map_for_each_entry(flowtrack_h->map_fd.flow, flow, {
        if (handle_bpf_entry(flowtrack_h, &flow, time_sec) != BPFW_RC_OK)
            return BPFW_RC_ERROR;
    });

    if (netlink_check_notifications(flowtrack_h->handle.netlink, new_bpf_interface, flowtrack_h) != BPFW_RC_OK)
        return BPFW_RC_ERROR;

    if (update_userspace_time(flowtrack_h, time_ns) != BPFW_RC_OK)
        return BPFW_RC_ERROR;

    return BPFW_RC_OK;
}


struct flowtrack_handle* flowtrack_init(struct cmd_args *args) {
    struct flowtrack_handle* flowtrack_h = (struct flowtrack_handle*)malloc(sizeof(struct flowtrack_handle));
    if (!flowtrack_h) {
        bpfw_error("Error allocating flowtrack handle: %s (-%d).\n", strerror(errno), errno);
        return NULL;
    }

    flowtrack_h->map_poll_sec = args->map_poll_sec;
    flowtrack_h->flow_timeout = args->flow_timeout;
    flowtrack_h->hook         = args->hook;

    bpfw_info("Initializing netlink ...\n");

    flowtrack_h->handle.netlink = netlink_init(args->if_count == 0, args->dsa);
    if (!flowtrack_h->handle.netlink)
        goto free;

    __u32 dsa_switch;
    char dsa_proto[DSA_PROTO_MAX_LEN];
    if (netlink_get_dsa(flowtrack_h->handle.netlink, &dsa_switch, dsa_proto) != BPFW_RC_OK)
        goto netlink_destroy;

    bpfw_info("Opening BPF object ...\n");

    flowtrack_h->handle.bpf = bpf_open_object(args->obj_path, args->hook);
    if (!flowtrack_h->handle.bpf)
        goto netlink_destroy;

    if (args->dsa && bpf_check_dsa(flowtrack_h->handle.bpf, dsa_switch, dsa_proto, &flowtrack_h->dsa_tag) != BPFW_RC_OK)
        goto bpf_unload_program;

    if (args->map_max_entries != FLOW_MAP_DEFAULT_MAX_ENTRIES && 
        bpf_set_map_max_entries(flowtrack_h->handle.bpf, FLOW_MAP_NAME, args->map_max_entries) != BPFW_RC_OK)
            goto bpf_unload_program;

    // Load the BPF object (including program and maps) into the kernel
    bpfw_info("Loading BPF program into kernel ...\n");

    if (bpf_load_program(flowtrack_h->handle.bpf) != BPFW_RC_OK)
        goto bpf_unload_program;

    flowtrack_h->map_fd.flow = bpf_get_map_fd(flowtrack_h->handle.bpf, FLOW_MAP_NAME);
    flowtrack_h->map_fd.user_time = bpf_get_map_fd(flowtrack_h->handle.bpf, USERSPACE_TIME_SECTION);
    if (flowtrack_h->map_fd.flow < 0 || flowtrack_h->map_fd.user_time < 0)
        goto bpf_unload_program;

    if (update_userspace_time(flowtrack_h, time_get_coarse_ns()) != BPFW_RC_OK)
        goto bpf_unload_program;

    bpfw_info("Attaching BPF program to network interfaces ...\n");

    // Attach the program to the specified interface names
    int rc = args->if_count == 0 ? attach_bpf_program(flowtrack_h->handle.bpf, flowtrack_h->handle.netlink) :
        bpf_ifnames_attach_program(flowtrack_h->handle.bpf, args->if_names, args->if_count);

    if (rc != BPFW_RC_OK)
        goto bpf_unload_program;

    bpfw_info("Initializing nf_conntrack ...\n");

    // Read the conntrack info and save it inside the BPF conntrack map
    flowtrack_h->handle.conntrack = conntrack_init();
    if (!flowtrack_h->handle.conntrack)
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
    conntrack_destroy(flowtrack_h->handle.conntrack);

bpf_detach_program:
    // Detach the program from the specified interface names
    args->if_count == 0 ? detach_bpf_program(flowtrack_h->handle.bpf, flowtrack_h->handle.netlink) :
        bpf_ifnames_detach_program(flowtrack_h->handle.bpf, args->if_names, args->if_count);

bpf_unload_program:
    // Unload the BPF object from the kernel
    bpf_unload_program(flowtrack_h->handle.bpf);

netlink_destroy:
    netlink_destroy(flowtrack_h->handle.netlink);

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
    conntrack_destroy(flowtrack_h->handle.conntrack);

    // Unload the BPF object from the kernel
    bpf_unload_program(flowtrack_h->handle.bpf);

    // Detach the program from the specified interface names
    args->if_count == 0 ? detach_bpf_program(flowtrack_h->handle.bpf, flowtrack_h->handle.netlink) :
        bpf_ifnames_detach_program(flowtrack_h->handle.bpf, args->if_names, args->if_count);

    // De-Init netlink
    netlink_destroy(flowtrack_h->handle.netlink);

    free(flowtrack_h);
}
