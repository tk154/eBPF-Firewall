#include "flowtrack.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <bpf/bpf.h>
#include <netinet/in.h>

#include "../bpf_loader/bpf_loader.h"
#include "../conntrack/conntrack.h"
#include "../netlink/netlink.h"

#include "../logging/logging.h"


struct flowtrack_handle {
    enum bpfw_hook hook;
    __u32 map_poll_sec;

    int flow_fd;
    int user_time_fd;

    // Flow Timeouts
    struct flow_timeout flow_timeout;
    struct dsa_tag *dsa_tag;

    struct bpf_handle *bpf_h;
    struct netlink_handle *netlink_h;
    struct conntrack_handle *conntrack_h;
};


static __u64 time_get_coarse_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_COARSE, &ts);

    return ts.tv_sec * (__u64)1e9 + ts.tv_nsec;
}

static __u32 time_ns_to_sec(__u64 ns) {
    return (__u32)(ns / (__u64)1e9);
}

static int update_userspace_time(struct flowtrack_handle *flowtrack_h, __u64 curr_time) {
    unsigned int index = 0;

    struct user_time user = {
        .timeout = 3 * flowtrack_h->map_poll_sec * (__u64)1e9, .last_time = curr_time
    };

    // Update the BPF flow entry, break out on error
    if (bpf_map_update_elem(flowtrack_h->user_time_fd, &index, &user, BPF_EXIST) != 0) {
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

    return bpf_ifindex_attach_program(flowtrack_h->bpf_h, ifindex);
}


static void connection_flowtable_offload(struct flow_key_value *flow) {
    if (flow->value.state == STATE_NEW_FLOW)
        bpfw_debug_key("\nConnection is offloaded to flowtable. Cannot read TCP state.\n", &flow->key);
}

static int connection_not_established(struct flow_key_value *flow) {
    /* It could be possible that we have received the package here through the BPF map
    *  before it was processed by nf_conntrack, or it has been dropped
    */
    if (flow->value.state == STATE_NEW_FLOW) {
        bpfw_debug_key("\nNon: ", &flow->key);

        flow->value.state = STATE_NONE;
        bpfw_debug_action("Act: ", flow->value.state);
    }

    return BPFW_RC_OK;
}

static int connection_established(struct flowtrack_handle *flowtrack_h, struct flow_key_value *flow, __u32 last_packet_sec_ago) {
    switch (flow->value.state) {
        case STATE_NONE:
            memset(&flow->value.next, 0, sizeof(flow->value.next));

        case STATE_NEW_FLOW:
            bpfw_debug_key("\nCon: ", &flow->key);

            // Since the TTL is decremented, we must increment the checksum for IPv4
            if (flow->key.family == AF_INET)
                flow->value.next.ipv4_cksum_diff = htons(0x0100);

            // Check for NAT
            conntrack_check_nat(flowtrack_h->conntrack_h, flow);
            
            int rc = netlink_get_next_hop(flowtrack_h->netlink_h, flow);
            switch (rc) {
                case BPFW_RC_ERROR:
                    return BPFW_RC_ERROR;

                case ACTION_FORWARD:
                    if (calc_l2_diff(flowtrack_h, flow) != BPFW_RC_OK) {
                        flow->value.state = STATE_PASS;
                        break;
                    }

                default:
                    flow->value.state = rc;
            }
            
            bpfw_debug_action("Act: ", flow->value.state);
            break;

        case STATE_FORWARD:
            // If there was a new package, update the nf_conntrack timeout
            if (last_packet_sec_ago < flowtrack_h->map_poll_sec &&
                conntrack_update_timeout(flowtrack_h->conntrack_h) != BPFW_RC_OK)
                    return BPFW_RC_ERROR;
    }

    return BPFW_RC_OK;
}


static int handle_bpf_entry(struct flowtrack_handle *flowtrack_h, struct flow_key_value *flow, __u32 time_sec) {
    __u32 flow_time_sec = time_ns_to_sec(flow->value.time);
    __u32 flow_timeout = flow->key.proto == IPPROTO_TCP ?
        flowtrack_h->flow_timeout.tcp : flowtrack_h->flow_timeout.udp;

    __u32 last_packet_sec_ago = time_sec - flow_time_sec;
    if (last_packet_sec_ago >= flow_timeout)
        // Flow timeout occured, so delete it from the BPF map
        return delete_bpf_entry(flowtrack_h->flow_fd, &flow->key);

    __u8 state = flow->value.state;
    int rc = conntrack_do_lookup(flowtrack_h->conntrack_h, flow);

    switch (rc) {
        case CT_CONN_FLOWTABLE_OFFLOAD:
            connection_flowtable_offload(flow);

        case CT_CONN_NOT_FOUND:
        case CT_CONN_NOT_ESTABLISHED:
            rc = connection_not_established(flow);
            break;

        case CT_CONN_ESTABLISHED:
            rc = connection_established(flowtrack_h, flow, last_packet_sec_ago);
            conntrack_free_ct_entry(flowtrack_h->conntrack_h);
            break;

        default:
            return BPFW_RC_ERROR;
    }

    if (rc != BPFW_RC_OK || state == flow->value.state)
        return rc;

    return update_bpf_entry(flowtrack_h->flow_fd, flow);
}

int flowtrack_update(struct flowtrack_handle* flowtrack_h) {
    struct flow_key_value flow;

    __u64 time_ns  = time_get_coarse_ns();
    __u32 time_sec = time_ns_to_sec(time_ns);

    // Iterate through all the flow entries
    bpf_flow_map_for_each_entry(flowtrack_h->flow_fd, flow, {
        if (handle_bpf_entry(flowtrack_h, &flow, time_sec) != BPFW_RC_OK)
            return BPFW_RC_ERROR;
    });

    if (netlink_check_notifications(flowtrack_h->netlink_h, new_bpf_interface, flowtrack_h) != BPFW_RC_OK)
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

    flowtrack_h->netlink_h = netlink_init(args->if_count == 0, args->dsa);
    if (!flowtrack_h->netlink_h)
        goto free;

    __u32 dsa_switch;
    char dsa_proto[DSA_PROTO_MAX_LEN];
    if (netlink_get_dsa(flowtrack_h->netlink_h, &dsa_switch, dsa_proto) != BPFW_RC_OK)
        goto netlink_destroy;

    bpfw_info("Opening BPF object ...\n");

    flowtrack_h->bpf_h = bpf_open_object(args->obj_path, args->hook);
    if (!flowtrack_h->bpf_h)
        goto netlink_destroy;

    if (args->dsa && bpf_check_dsa(flowtrack_h->bpf_h, dsa_switch, dsa_proto, &flowtrack_h->dsa_tag) != BPFW_RC_OK)
        goto bpf_unload_program;

    if (args->map_max_entries != FLOW_MAP_DEFAULT_MAX_ENTRIES && 
        bpf_set_map_max_entries(flowtrack_h->bpf_h, FLOW_MAP_NAME, args->map_max_entries) != BPFW_RC_OK)
            goto bpf_unload_program;

    // Load the BPF object (including program and maps) into the kernel
    bpfw_info("Loading BPF program into kernel ...\n");

    if (bpf_load_program(flowtrack_h->bpf_h) != BPFW_RC_OK)
        goto bpf_unload_program;

    flowtrack_h->flow_fd = bpf_get_map_fd(flowtrack_h->bpf_h, FLOW_MAP_NAME);
    flowtrack_h->user_time_fd = bpf_get_map_fd(flowtrack_h->bpf_h, USERSPACE_TIME_SECTION);
    if (flowtrack_h->flow_fd < 0 || flowtrack_h->user_time_fd < 0)
        goto bpf_unload_program;

    if (update_userspace_time(flowtrack_h, time_get_coarse_ns()) != BPFW_RC_OK)
        goto bpf_unload_program;

    bpfw_info("Attaching BPF program to network interfaces ...\n");

    // Attach the program to the specified interface names
    int rc = args->if_count == 0 ? bpf_attach_program(flowtrack_h->bpf_h, flowtrack_h->netlink_h) :
        bpf_ifnames_attach_program(flowtrack_h->bpf_h, args->if_names, args->if_count);

    if (rc != BPFW_RC_OK)
        goto bpf_unload_program;

    bpfw_info("Initializing nf_conntrack ...\n");

    // Read the conntrack info and save it inside the BPF conntrack map
    flowtrack_h->conntrack_h = conntrack_init();
    if (!flowtrack_h->conntrack_h)
        goto bpf_detach_program;

    return flowtrack_h;

conntrack_destroy:
    // De-Init conntrack
    conntrack_destroy(flowtrack_h->conntrack_h);

bpf_detach_program:
    // Detach the program from the specified interface names
    args->if_count == 0 ? bpf_detach_program(flowtrack_h->bpf_h, flowtrack_h->netlink_h) :
        bpf_ifnames_detach_program(flowtrack_h->bpf_h, args->if_names, args->if_count);

bpf_unload_program:
    // Unload the BPF object from the kernel
    bpf_unload_program(flowtrack_h->bpf_h);

netlink_destroy:
    netlink_destroy(flowtrack_h->netlink_h);

free:
    free(flowtrack_h);

    return NULL;
}

void flowtrack_destroy(struct flowtrack_handle* flowtrack_h, struct cmd_args *args) {
    // De-Init conntrack
    conntrack_destroy(flowtrack_h->conntrack_h);

    // Unload the BPF object from the kernel
    bpf_unload_program(flowtrack_h->bpf_h);

    // Detach the program from the specified interface names
    args->if_count == 0 ? bpf_detach_program(flowtrack_h->bpf_h, flowtrack_h->netlink_h) :
        bpf_ifnames_detach_program(flowtrack_h->bpf_h, args->if_names, args->if_count);

    // De-Init netlink
    netlink_destroy(flowtrack_h->netlink_h);

    free(flowtrack_h);
}
